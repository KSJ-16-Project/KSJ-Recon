"""Core integration entry point for the lightweight XSS module."""

from __future__ import annotations

import asyncio
import atexit
import json
import logging
import signal
import sys
from pathlib import Path
from datetime import datetime
from typing import Callable
from urllib.parse import urlparse

from .browser_verifier import BrowserVerifier
from .dom_hash_xss import DOMHashXSSVerifier
from .dom_stored_xss import DOMStoredXSSVerifier
from .http_client import HttpClient
from .reflected_xss import ReflectedXSSScanner
from .result_builder import ResultBuilder
from .stored_xss import StoredXSSScanner
from .target_extractor import TargetExtractor

logger = logging.getLogger(__name__)

DEFAULT_OPTIONS = {
    "browser_verify": True,
    "stored_xss": True,
    "dom_hash_xss": True,
    "dom_stored_xss": False,
    "timeout": 10,
    "verify_tls": False,
    "request_delay": 0.0,   # seconds between HTTP requests; increase to avoid IP blocks
    "test_attack_params_only": False,
    "max_params_per_target": 3,
}

# Global reference for SIGINT handler
_current_scanner: XSSScanner | None = None


def _handle_sigint(_sig, _frame):
    if _current_scanner is not None:
        _current_scanner.save_partial()
    sys.exit(0)


signal.signal(signal.SIGINT, _handle_sigint)


async def run_xss_scan(input_json: dict, *, cookies_refresher: Callable[[], dict] | None = None) -> dict:
    scanner = XSSScanner(input_json, cookies_refresher=cookies_refresher)
    # Run the scan in a worker thread so Playwright sync APIs never execute
    # inside the active asyncio event loop thread.
    output = await asyncio.to_thread(scanner.run)
    scanner.mark_final_saved()
    scanner.cleanup_partial()
    return output


class XSSScanner:
    def __init__(self, input_data: dict, *, cookies_refresher: Callable[[], dict] | None = None):
        global _current_scanner
        _current_scanner = self
        self._cookies_refresher = cookies_refresher

        if "xss_data" in input_data and isinstance(input_data["xss_data"], dict):
            input_data = input_data["xss_data"]

        self.input_data = input_data
        self.base_url = self._resolve_base_url(input_data)
        self.options = {**DEFAULT_OPTIONS, **input_data.get("options", {})}
        self.targets = TargetExtractor(input_data).extract()
        self.builder = ResultBuilder()
        self.client = HttpClient(
            headers=input_data.get("headers", {}),
            cookies=input_data.get("cookies", {}),
            timeout=int(self.options["timeout"]),
            verify_tls=bool(self.options["verify_tls"]),
            request_delay=float(self.options.get("request_delay", 0.0)),
        )
        self.errors: list[dict] = []
        self.skipped: list[dict] = []
        self._partial_results: list[dict] = []
        self._partial_saved: bool = False
        self._final_saved: bool = False
        self._auth_applied: bool = False  # set to True when auth credentials are present

        self._init_auth(input_data)

        # Warn early if no targets were extracted so users can distinguish
        # "zero findings" from "misconfigured input"
        if not self.targets:
            logger.warning("no targets extracted – check input.json 'urls' / 'spider_urls' field")

        # atexit ensures partial results are written even when Node.js crashes
        # with SIGABRT (which bypasses the SIGINT handler above)
        atexit.register(self._atexit_save)

    def _resolve_base_url(self, input_data: dict) -> str:
        """Resolve base_url from explicit value or the first absolute crawled URL."""
        explicit = input_data.get("base_url")
        if explicit:
            return explicit

        for key in ("spider_urls", "urls"):
            for item in input_data.get(key, []):
                url = item.get("url") if isinstance(item, dict) else item
                if not isinstance(url, str):
                    continue
                parsed = urlparse(url)
                if parsed.scheme and parsed.netloc:
                    base_url = f"{parsed.scheme}://{parsed.netloc}"
                    logger.info("base_url 자동 설정: %s (%s 첫 번째 항목에서 추출)", base_url, key)
                    return base_url

        raise ValueError(
            "base_url이 없고 spider_urls/urls에서도 기준 URL을 추출할 수 없습니다. "
            "base_url 또는 최소 1개 이상의 절대 URL을 입력해주세요."
        )

    def _set_partial_results(self, results: list[dict]) -> None:
        self._partial_results = list(results)
        self._partial_saved = False

    def _init_auth(self, input_data: dict) -> None:
        """Apply auth from input JSON or fall back to ksj_login."""
        session_id = input_data.get("session_id")
        token = input_data.get("token")

        self.client.update_auth(session_id=session_id, token=token)
        self._auth_applied = bool(session_id or token or input_data.get("cookies"))

        self._register_auth_credentials(input_data.get("auth"))

        if not self._auth_applied:
            cookies = self._ksj_get_cookies()
            if cookies:
                self.client.update_auth(cookies=cookies)
                self._auth_applied = True

    def _register_auth_credentials(self, auth: dict | None) -> None:
        """Forward form_login credentials from input.json to ksj_login."""
        if not isinstance(auth, dict):
            return
        login_url = auth.get("login_url")
        username = auth.get("username")
        password = auth.get("password")
        if not (login_url and username and password):
            return
        try:
            import ksj_login
            ksj_login.store_credentials(login_url, username, password)
            logger.info("ksj_login credentials registered from input.json (%s)", login_url)
        except Exception as e:
            logger.warning("failed to register ksj_login credentials: %s", e)

    def _ksj_get_cookies(self) -> dict | None:
        """Acquire cookies from ksj_login; returns None if unavailable or failed."""
        try:
            import ksj_login
            if not ksj_login.has_credentials():
                return None
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                result = ex.submit(lambda: asyncio.run(ksj_login.get_session())).result()
            if result.success:
                logger.info("auth acquired from ksj_login")
                return ksj_login.to_cookie_dict(result.cookies)
            logger.warning("ksj_login session failed: %s", result.reason)
        except Exception as e:
            logger.warning("ksj_login error: %s", e)
        return None

    def _refresh_auth(self) -> None:
        """Refresh session via cookies_refresher or ksj_login fallback."""
        if self._cookies_refresher is not None:
            try:
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                    new_cookies = ex.submit(self._cookies_refresher).result()
                self.client.update_auth(cookies=new_cookies)
                logger.info("session refreshed via cookies_refresher")
            except Exception as e:
                logger.warning("cookies_refresher failed: %s", e)
            return

        cookies = self._ksj_get_cookies()
        if cookies:
            self.client.update_auth(cookies=cookies)
            logger.info("session refreshed via ksj_login")

    def save_partial(self) -> None:
        if self._final_saved:
            return
        output = self.builder.build(
            base_url=self.base_url,
            results=self._partial_results,
            errors=self.errors,
            total_targets=len(self.targets),
            options={**self.options, "partial": True, "auth_applied": self._auth_applied},
            skipped=self.skipped,
        )
        results_dir = Path(self.input_data.get("results_dir", "results"))
        results_dir.mkdir(parents=True, exist_ok=True)
        path = results_dir / "xss_result_partial.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(output, f, ensure_ascii=False, indent=2)
        self._partial_saved = True
        logger.debug("partial saved: %s", path)

    def _save_checkpoint(self) -> None:
        """Save intermediate results without raising; called after each scan phase."""
        try:
            self.save_partial()
        except Exception as e:
            logger.debug("checkpoint save failed: %s", e)

    def _atexit_save(self) -> None:
        """Called by atexit when the process exits (including SIGABRT crashes)."""
        if self._final_saved:
            return
        if self._partial_results and not self._partial_saved:
            try:
                self.save_partial()
            except Exception:
                pass

    def mark_final_saved(self) -> None:
        """Disable partial autosave after the final report is written."""
        self._final_saved = True
        self._partial_results = []
        self._partial_saved = True

    def cleanup_partial(self) -> None:
        results_dir = Path(self.input_data.get("results_dir", "results"))
        partial_path = results_dir / "xss_result_partial.json"
        try:
            if partial_path.exists():
                partial_path.unlink()
                logger.info("partial result removed: %s", partial_path)
        except Exception as e:
            logger.warning("failed to remove partial result: %s", e)

    def run(self) -> dict:
        logger.info("XSS scan started: %s targets", len(self.targets))
        results: list[dict] = []

        logger.info("phase: reflected XSS (%d targets)", len(self.targets))
        reflected = ReflectedXSSScanner(
            self.targets, self.client, self.builder,
            auth_refresher=self._refresh_auth,
        )
        reflected.configure(
            test_attack_params_only=bool(self.options.get("test_attack_params_only", False)),
            max_params_per_target=int(self.options.get("max_params_per_target", 3)),
        )
        results.extend(reflected.scan())
        results.extend(reflected.scan_headers())
        self._set_partial_results(results)
        self.errors.extend(reflected.errors)
        self._save_checkpoint()

        if self.options.get("stored_xss"):
            logger.info("phase: stored XSS (%d targets)", len(self.targets))
            stored = StoredXSSScanner(
                self.targets, self.client, self.builder,
                auth_refresher=self._refresh_auth,
            )
            results.extend(stored.scan())
            self._set_partial_results(results)
            self.errors.extend(stored.errors)
            self.skipped.extend(stored.skipped)
            self._save_checkpoint()

        if self.options.get("dom_hash_xss"):
            logger.info("phase: DOM hash XSS")
            dom = DOMHashXSSVerifier(
                self.targets, self.builder,
                verify_tls=bool(self.options.get("verify_tls", False)),
                auth_cookies={k: v for k, v in self.client.session.cookies.items()},
                auth_headers=dict(self.client.session.headers),
            )
            results.extend(dom.scan())
            self._set_partial_results(results)
            self.errors.extend(dom.errors)
            self._save_checkpoint()

        if self.options.get("dom_stored_xss"):
            logger.info("phase: DOM stored XSS")
            dom_stored = DOMStoredXSSVerifier(
                self.targets, self.builder,
                verify_tls=bool(self.options.get("verify_tls", False)),
                timeout_ms=int(self.options["timeout"]) * 1000,
                auth_cookies={k: v for k, v in self.client.session.cookies.items()},
                auth_headers=dict(self.client.session.headers),
            )
            results.extend(dom_stored.scan())
            self._set_partial_results(results)
            self.errors.extend(dom_stored.errors)
            self.skipped.extend(dom_stored.skipped)
            self._save_checkpoint()

        if self.options.get("browser_verify"):
            # Save checkpoint BEFORE browser verification: this is where crashes
            # happen most often (Node.js / Playwright process).
            self._save_checkpoint()
            logger.info("phase: browser verification")
            auth_cookies = {k: v for k, v in self.client.session.cookies.items()}
            auth_headers = dict(self.client.session.headers)
            verifier = BrowserVerifier(
                auth_cookies=auth_cookies,
                auth_headers=auth_headers,
                timeout_ms=int(self.options["timeout"]) * 1000,
                verify_tls=bool(self.options.get("verify_tls", False)),
            )
            results = verifier.verify(results)
            self.errors.extend(verifier.errors)
            self._set_partial_results(results)

        return self.builder.build(
            base_url=self.base_url,
            results=results,
            errors=self.errors,
            total_targets=len(self.targets),
            options={**self.options, "auth_applied": self._auth_applied},
            skipped=self.skipped,
        )


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Lightweight XSS module")
    parser.add_argument("input", nargs="?", default="input.json")
    parser.add_argument("-o", "--output", default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="show scan progress logs")
    args = parser.parse_args()
    log_level = logging.INFO if args.verbose else logging.CRITICAL
    logging.basicConfig(level=log_level, format="[%(levelname)s] %(message)s")

    with open(args.input, "r", encoding="utf-8") as f:
        input_data = json.load(f)
    scanner = XSSScanner(input_data)
    output = scanner.run()

    out_path = args.output
    if not out_path:
        # Use results_dir from input_data (same as save_partial) for consistency
        results_dir = Path(input_data.get("results_dir", "results"))
        results_dir.mkdir(exist_ok=True)
        out_path = results_dir / f"xss_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    # 최종 결과 파일 저장에 성공하면 partial autosave 파일은 삭제합니다.
    # partial은 비정상 종료 복구용 임시 파일이므로 정상 완료 후에는 남기지 않습니다.
    scanner.mark_final_saved()
    scanner.cleanup_partial()


if __name__ == "__main__":
    main()
