import subprocess
import json
import os
import platform
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


class AggressiveFuzzer:
    """
    K-Shield Jr. Recon 모듈 - Portable Fuzzer.
    번들링된 ffuf 바이너리로 디렉토리/서브도메인 퍼징을 수행하고,
    AI 파이프라인용 정규화 스키마로 결과를 반환한다.
    """

    MODULE_NAME = "fuzzer_portable"

    # 모드별 기본 워드리스트
    DEFAULT_WORDLISTS = {
        "directory": "common.txt",
        "subdomain": "subdomains-top5000.txt",
    }

    def __init__(self, target: str):
        self.target = target.rstrip("/")
        self.base_dir = Path(__file__).resolve().parent
        self.ffuf_bin = self._get_binary_path()
        self._ensure_executable()

    # ---------- 바이너리 / 워드리스트 ----------
    def _get_binary_path(self) -> Path:
        binary_map = {
            "Darwin":  "ffuf_mac",
            "Windows": "ffuf.exe",
            "Linux":   "ffuf_linux",
        }
        return self.base_dir / "bin" / binary_map.get(platform.system(), "ffuf_linux")

    def _ensure_executable(self):
        if platform.system() != "Windows" and self.ffuf_bin.exists():
            os.chmod(self.ffuf_bin, 0o755)

    def _resolve_wordlist(self, wordlist: str) -> Path:
        p = Path(wordlist)
        if p.is_absolute():
            return p
        return self.base_dir / "wordlists" / wordlist

    # ---------- 모드별 URL 빌더 ----------
    def _build_target_urls(self, mode: str, try_https: bool = True) -> list:
        """
        디렉토리 모드: [http(s)://target/FUZZ]  (기존 스킴 유지)
        서브도메인 모드: [http://FUZZ.host, https://FUZZ.host]
        """
        parsed = urlparse(self.target)

        if mode == "directory":
            return [f"{self.target}/FUZZ"]

        elif mode == "subdomain":
            host = parsed.netloc.split(":")[0] if parsed.netloc else parsed.path
            urls = [f"http://FUZZ.{host}"]
            if try_https:
                urls.append(f"https://FUZZ.{host}")
            return urls

        else:
            raise ValueError(f"지원하지 않는 모드: {mode}")

    # ---------- 메인 실행 ----------
    def run_fuzz(
        self,
        wordlist: str = None,
        mode: str = "directory",
        timeout_sec: int = 600,
        try_https: bool = True,
        save_to: str = None,
        **options,
    ) -> dict:
        """
        :param wordlist: 워드리스트 파일명 또는 절대경로 (None이면 모드별 기본값)
        :param mode: "directory" | "subdomain"
        :param timeout_sec: 전체 프로세스 타임아웃
        :param try_https: 서브도메인 모드에서 https도 시도할지
        :param save_to: 결과 저장 경로
                        - None: 저장 안 함
                        - "auto": results/ 폴더에 자동 파일명 생성
                        - "경로/파일명.json": 직접 지정
        :return: 정규화된 결과 dict
        """
        if not self.ffuf_bin.exists():
            return self._error(f"엔진 없음: {self.ffuf_bin}", mode)

        # 모드별 기본 워드리스트
        if wordlist is None:
            wordlist = self.DEFAULT_WORDLISTS[mode]
        wordlist_path = self._resolve_wordlist(wordlist)
        if not wordlist_path.exists():
            return self._error(f"워드리스트 없음: {wordlist_path}", mode)

        target_urls = self._build_target_urls(mode, try_https=try_https)
        all_results = []
        warnings = []

        # 서브도메인 모드는 http/https 둘 다 돌릴 수 있음
        for target_url in target_urls:
            output_file = Path(tempfile.gettempdir()) / f"ffuf_{uuid.uuid4().hex}.json"
            try:
                cmd = self._compose_command(
                    target_url=target_url,
                    wordlist=str(wordlist_path),
                    output_file=str(output_file),
                    mode=mode,
                    **options,
                )
                print(f"[*] {mode} 퍼징: {target_url}")

                try:
                    subprocess.run(
                        cmd,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE,
                        timeout=timeout_sec,
                        check=False,
                    )
                except subprocess.TimeoutExpired:
                    warnings.append(f"타임아웃: {target_url}")

                all_results.extend(self._parse_output(output_file, mode))

            finally:
                if output_file.exists():
                    output_file.unlink()

        # 서브도메인 모드: http/https 중복 제거 (host 기준)
        if mode == "subdomain":
            all_results = self._dedupe_subdomains(all_results)

        result = {
            "status": "ok",
            "module": self.MODULE_NAME,
            "mode": mode,
            "target": self.target,
            "results": all_results,
        }
        if warnings:
            result["warnings"] = warnings

        # 저장 옵션 처리
        if save_to == "auto":
            self.save_results(result)
        elif save_to:
            self.save_results(result, output_path=save_to)

        return result

    # ---------- 명령어 조립 ----------
    def _compose_command(
        self,
        target_url: str,
        wordlist: str,
        output_file: str,
        mode: str,
        **options,
    ) -> list:
        cmd = [
            str(self.ffuf_bin),
            "-u", target_url,
            "-w", wordlist,
            "-o", output_file,
            "-of", "json",
            "-s",
            "-t", str(options.get("threads", 100)),
        ]

        # 모드별 기본 필터 정책
        if mode == "directory":
            cmd += ["-fc", options.get("filter_code", "404")]
        elif mode == "subdomain":
            cmd += ["-ac"]   # 와일드카드 DNS 자동 보정
            if "filter_size" in options:
                cmd += ["-fs", str(options["filter_size"])]

        # 공통 옵션
        if "match_code" in options:
            cmd += ["-mc", options["match_code"]]
        if "extensions" in options and mode == "directory":
            cmd += ["-e", options["extensions"]]
        if "timeout" in options:
            cmd += ["-timeout", str(options["timeout"])]
        if "proxy" in options:
            cmd += ["-x", options["proxy"]]
        for h in options.get("headers", []):
            cmd += ["-H", h]

        # 확장성: 정의 안 된 옵션도 그대로 주입
        cmd += list(options.get("custom_args", []))
        return cmd

    # ---------- 정규화 ----------
    def _parse_output(self, output_file: Path, mode: str) -> list:
        if not output_file.exists() or output_file.stat().st_size == 0:
            return []
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except json.JSONDecodeError:
            return []

        normalized = []
        for item in raw.get("results", []):
            url = item.get("url", "")
            entry = {
                "url": url,
                "status": item.get("status", 0),
                "length": item.get("length", 0),
                "module": self.MODULE_NAME,
                "mode": mode,
            }
            if mode == "subdomain":
                parsed = urlparse(url)
                entry["host"] = parsed.netloc
                entry["scheme"] = parsed.scheme
            normalized.append(entry)
        return normalized

    def _dedupe_subdomains(self, results: list) -> list:
        """같은 host의 http/https 결과를 하나로 합치되, schemes 리스트로 보존"""
        merged = {}
        for r in results:
            host = r.get("host", r["url"])
            if host not in merged:
                merged[host] = {**r, "schemes": [r.get("scheme", "http")]}
            else:
                schemes = merged[host]["schemes"]
                if r.get("scheme") and r["scheme"] not in schemes:
                    schemes.append(r["scheme"])

        final = []
        for host, r in merged.items():
            r.pop("scheme", None)
            final.append(r)
        return final

    # ---------- 결과 저장 ----------
    def save_results(
        self,
        result: dict,
        output_path: str = None,
        results_dir: str = "results",
    ) -> Path:
        """
        결과 dict를 JSON 파일로 저장한다.
        :param result: run_fuzz()가 반환한 dict
        :param output_path: 절대/상대 경로 직접 지정 (None이면 자동 생성)
        :param results_dir: output_path 미지정 시 저장할 디렉토리명
        :return: 저장된 파일의 Path 객체
        """
        if output_path:
            save_path = Path(output_path)
            if not save_path.is_absolute():
                save_path = self.base_dir / save_path
        else:
            # 자동 파일명: results/fuzzer_{mode}_{host}_{timestamp}.json
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            host = urlparse(self.target).netloc or self.target
            safe_host = "".join(c if c.isalnum() or c in "-_" else "_" for c in host)
            mode = result.get("mode", "unknown")
            filename = f"fuzzer_{mode}_{safe_host}_{timestamp}.json"

            save_dir = self.base_dir / results_dir
            save_dir.mkdir(parents=True, exist_ok=True)
            save_path = save_dir / filename

        # 부모 디렉토리 자동 생성
        save_path.parent.mkdir(parents=True, exist_ok=True)

        with open(save_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        print(f"[+] 결과 저장: {save_path}")
        return save_path

    def _error(self, msg: str, mode: str) -> dict:
        return {
            "status": "error",
            "module": self.MODULE_NAME,
            "mode": mode,
            "target": self.target,
            "results": [],
            "error": msg,
        }


# --- 실행부 ---
if __name__ == "__main__":
    target = "https://pentest-ground.com"
    fuzzer = AggressiveFuzzer(target)

    # ---------- 모드 1: 디렉토리 퍼징 (자동 저장) ----------
    print("\n--- [모드 1] 디렉토리 퍼징 ---")
    res1 = fuzzer.run_fuzz(
        mode="directory",
        threads=50,
        timeout_sec=300,
        save_to="auto",   # results/ 폴더에 자동 파일명으로 저장
    )
    print(f"발견: {len(res1['results'])}개\n")

    for item in res1['results']:
        print(f"  [{item['status']}] {item['url']}  (length: {item['length']})")

    # ---------- 모드 2: 서브도메인 퍼징 (경로 직접 지정) ----------
    print("\n--- [모드 2] 서브도메인 퍼징 ---")
    res2 = fuzzer.run_fuzz(
        mode="subdomain",
        wordlist="shubs-subdomains.txt",
        threads=80,
        timeout_sec=300,
        try_https=True,
        save_to="results/juice_shop_subdomains.json",   # 경로 직접 지정
    )
    print(f"발견: {len(res2['results'])}개\n")

    for item in res2['results']:
        schemes = ",".join(item.get('schemes', ['http']))
        print(f"  [{item['status']}] {item.get('host', item['url'])}  ({schemes})  length: {item['length']}")