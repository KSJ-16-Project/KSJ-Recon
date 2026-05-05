"""Core integration entry point for the lightweight XSS module."""

from __future__ import annotations

import json
import logging
import signal
import sys
from pathlib import Path
from datetime import datetime
from typing import Callable

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
}

# Global reference for SIGINT handler
_current_scanner: XSSScanner | None = None


def _handle_sigint(_sig, _frame):
    print("\n[interrupted] saving partial results...")
    if _current_scanner is not None:
        _current_scanner.save_partial()
    sys.exit(0)


signal.signal(signal.SIGINT, _handle_sigint)


def run_xss_scan(input_json: dict, *, cookies_refresher: Callable[[], dict] | None = None) -> dict:
    scanner = XSSScanner(input_json, cookies_refresher=cookies_refresher)
    return scanner.run()


class XSSScanner:
    def __init__(self, input_data: dict, *, cookies_refresher: Callable[[], dict] | None = None):
        global _current_scanner
        _current_scanner = self
        self._cookies_refresher = cookies_refresher

        self.input_data = input_data
        self.base_url = input_data.get("base_url", "")
        if not self.base_url:
            raise ValueError("base_url is required")
        self.options = {**DEFAULT_OPTIONS, **input_data.get("options", {})}
        self.targets = TargetExtractor(input_data).extract()
        self.builder = ResultBuilder()
        self.client = HttpClient(
            headers=input_data.get("headers", {}),
            cookies=input_data.get("cookies", {}),
            timeout=int(self.options["timeout"]),
            verify_tls=bool(self.options["verify_tls"]),
        )
        self.evidence_dir = Path(input_data.get("evidence_dir", Path(__file__).resolve().parent.parent / "evidence"))
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.errors: list[dict] = []
        self._partial_results: list[dict] = []

        self._login_mock_path: Path | None = (
            Path(input_data["login_mock_path"]) if input_data.get("login_mock_path") else None
        )
        self._init_auth(input_data)

    def _init_auth(self, input_data: dict) -> None:
        """Apply auth from input JSON or fall back to login.py."""
        session_id = input_data.get("session_id")
        token = input_data.get("token")

        if not session_id and not token:
            logger.info("no auth in input – trying login.py")
            try:
                from .login import get_auth
                auth = get_auth(self._login_mock_path)
                session_id = auth.get("session_id")
                token = auth.get("token")
                logger.info("auth loaded from login.py")
            except FileNotFoundError as e:
                logger.warning("login.py: %s – proceeding without auth", e)
            except Exception as e:
                logger.warning("login.py error: %s – proceeding without auth", e)

        self.client.update_auth(session_id=session_id, token=token)

    def _refresh_auth(self) -> None:
        """Refresh session via cookies_refresher (ksj_login) or fallback to login.py."""
        if self._cookies_refresher is not None:
            try:
                new_cookies = self._cookies_refresher()
                self.client.update_auth(cookies=new_cookies)
                logger.info("session refreshed via cookies_refresher")
            except Exception as e:
                logger.warning("cookies_refresher failed: %s", e)
            return

        try:
            from .login import get_auth
            auth = get_auth(self._login_mock_path)
            self.client.update_auth(
                session_id=auth.get("session_id"),
                token=auth.get("token"),
            )
            logger.info("session refreshed via login.py")
        except Exception as e:
            logger.warning("session refresh failed: %s", e)

    def save_partial(self) -> None:
        output = self.builder.build(
            base_url=self.base_url,
            results=self._partial_results,
            errors=self.errors,
            total_targets=len(self.targets),
            options={**self.options, "partial": True},
        )
        results_dir = Path(self.input_data.get("results_dir", "results"))
        results_dir.mkdir(parents=True, exist_ok=True)
        path = results_dir / "xss_result_partial.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(output, f, ensure_ascii=False, indent=2)
        print(f"[saved] {path}")

    def run(self) -> dict:
        logger.info("XSS scan started: %s targets", len(self.targets))
        results: list[dict] = []

        reflected = ReflectedXSSScanner(
            self.targets, self.client, self.builder,
            auth_refresher=self._refresh_auth,
        )
        results.extend(reflected.scan())
        results.extend(reflected.scan_headers())
        self._partial_results = list(results)
        self.errors.extend(reflected.errors)

        if self.options.get("stored_xss"):
            stored = StoredXSSScanner(
                self.targets, self.client, self.builder,
                auth_refresher=self._refresh_auth,
            )
            results.extend(stored.scan())
            self._partial_results = list(results)
            self.errors.extend(stored.errors)

        if self.options.get("dom_hash_xss"):
            dom = DOMHashXSSVerifier(self.targets, self.builder, self.evidence_dir)
            results.extend(dom.scan())
            self._partial_results = list(results)
            self.errors.extend(dom.errors)

        if self.options.get("dom_stored_xss"):
            dom_stored = DOMStoredXSSVerifier(self.targets, self.builder, self.evidence_dir)
            results.extend(dom_stored.scan())
            self._partial_results = list(results)
            self.errors.extend(dom_stored.errors)

        if self.options.get("browser_verify"):
            auth_cookies = dict(self.client.session.cookies)
            auth_headers = dict(self.client.session.headers)
            verifier = BrowserVerifier(
                self.evidence_dir,
                auth_cookies=auth_cookies,
                auth_headers=auth_headers,
            )
            results = verifier.verify(results)
            self._partial_results = list(results)

        return self.builder.build(
            base_url=self.base_url,
            results=results,
            errors=self.errors,
            total_targets=len(self.targets),
            options=self.options,
        )


def main() -> None:
    import argparse
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    parser = argparse.ArgumentParser(description="Lightweight XSS module")
    parser.add_argument("input", nargs="?", default="input.json")
    parser.add_argument("-o", "--output", default=None)
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        input_data = json.load(f)
    output = run_xss_scan(input_data)

    out_path = args.output
    if not out_path:
        results_dir = Path("results")
        results_dir.mkdir(exist_ok=True)
        out_path = results_dir / f"xss_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
    print(out_path)


if __name__ == "__main__":
    main()
