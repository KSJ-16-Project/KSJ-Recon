"""
K-Shield Jr. Recon 모듈 - Portable Fuzzer (Core 통합용)

Core 시스템에서 import하여 사용하는 순수 모듈.
인터랙티브 UI나 출력 로직은 별도 CLI 파일(fuzzer_cli.py)에 있다.

사용 예시:
    from fuzzer_module import AggressiveFuzzer
    
    fuzzer = AggressiveFuzzer("http://target.com")
    result = fuzzer.run_fuzz(
        mode="directory",
        recursion=True,
        recursion_depth=2,
        threads=20,
        save_to="auto",
    )
    # result["status"], result["results"] 사용
"""

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
    번들링된 ffuf 바이너리로 디렉토리/서브도메인 퍼징을 수행하고,
    AI 파이프라인용 정규화 스키마로 결과를 반환한다.

    공통 반환 스키마:
        {
            "status": "ok" | "error",
            "module": "fuzzer_portable",
            "mode": "directory" | "subdomain",
            "target": str,
            "results": [
                {
                    "url": str,
                    "status": int,
                    "length": int,
                    "module": "fuzzer_portable",
                    "mode": str,
                    # subdomain 모드일 때만:
                    "host": str,
                    "schemes": ["http", "https"],
                    # directory + recursion일 때만:
                    "depth": int,
                },
                ...
            ],
            # 옵션 필드
            "recursion": {"enabled": bool, "depth": int},
            "warnings": [str, ...],
            "error": str,
        }
    """

    MODULE_NAME = "fuzzer_portable"

    # 모드별 기본 워드리스트
    DEFAULT_WORDLISTS = {
        "directory": "common.txt",
        "subdomain": "shubs-subdomains.txt",
    }

    def __init__(self, target: str):
        """
        :param target: 퍼징 대상 URL (예: http://example.com)
        """
        self.target = target.rstrip("/")
        self.base_dir = Path(__file__).resolve().parent
        self.ffuf_bin = self._get_binary_path()
        self._ensure_executable()

    # ---------- 바이너리 / 워드리스트 ----------
    def _get_binary_path(self) -> Path:
        """OS별 번들링된 ffuf 바이너리 경로 반환"""
        binary_map = {
            "Darwin":  "ffuf_mac",
            "Windows": "ffuf.exe",
            "Linux":   "ffuf_linux",
        }
        return self.base_dir / "bin" / binary_map.get(platform.system(), "ffuf_linux")

    def _ensure_executable(self):
        """macOS/Linux에서 바이너리 실행 권한 부여"""
        if platform.system() != "Windows" and self.ffuf_bin.exists():
            os.chmod(self.ffuf_bin, 0o755)

    def _resolve_wordlist(self, wordlist: str) -> Path:
        """절대경로면 그대로, 아니면 wordlists/ 디렉토리에서 탐색"""
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
        recursion: bool = False,
        recursion_depth: int = 2,
        verbose: bool = False,
        **options,
    ) -> dict:
        """
        퍼징을 실행하고 정규화된 결과 dict를 반환한다.

        :param wordlist: 워드리스트 파일명 또는 절대경로 (None이면 모드별 기본값)
        :param mode: "directory" | "subdomain"
        :param timeout_sec: 전체 프로세스 타임아웃
        :param try_https: 서브도메인 모드에서 https도 시도할지
        :param save_to: 결과 저장 경로
                        - None: 저장 안 함
                        - "auto": results/ 폴더에 자동 파일명 생성
                        - "경로/파일.json": 직접 지정
        :param recursion: 발견된 디렉토리 안을 재귀적으로 탐색할지 (directory 모드만)
        :param recursion_depth: 재귀 최대 깊이
        :param verbose: True면 진행 상황 로그 출력 (Core 통합 시 보통 False)
        :param options: ffuf 추가 옵션
                        - threads (default: 100)
                        - filter_code, match_code, filter_size
                        - extensions, headers, proxy, timeout
                        - custom_args (list): 정의되지 않은 옵션 그대로 주입
        :return: 정규화된 결과 dict (위 docstring의 공통 반환 스키마 참조)
        """
        if not self.ffuf_bin.exists():
            return self._error(f"엔진 없음: {self.ffuf_bin}", mode)

        # 모드별 기본 워드리스트
        if wordlist is None:
            wordlist = self.DEFAULT_WORDLISTS[mode]
        wordlist_path = self._resolve_wordlist(wordlist)
        if not wordlist_path.exists():
            return self._error(f"워드리스트 없음: {wordlist_path}", mode)

        # 재귀 옵션은 directory 모드만 의미 있음 - 안전장치
        if recursion and mode != "directory":
            recursion = False

        target_urls = self._build_target_urls(mode, try_https=try_https)
        all_results = []
        warnings = []

        for target_url in target_urls:
            output_file = Path(tempfile.gettempdir()) / f"ffuf_{uuid.uuid4().hex}.json"
            try:
                cmd = self._compose_command(
                    target_url=target_url,
                    wordlist=str(wordlist_path),
                    output_file=str(output_file),
                    mode=mode,
                    recursion=recursion,
                    recursion_depth=recursion_depth,
                    **options,
                )

                if verbose:
                    if recursion:
                        print(f"[fuzzer] {mode} 퍼징 (재귀 depth={recursion_depth}): {target_url}")
                    else:
                        print(f"[fuzzer] {mode} 퍼징: {target_url}")

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

        # 서브도메인 모드: http/https 중복 제거
        if mode == "subdomain":
            all_results = self._dedupe_subdomains(all_results)

        # 디렉토리 모드 + 재귀: depth 정보 추가
        if mode == "directory" and recursion:
            all_results = self._annotate_depth(all_results)

        result = {
            "status": "ok",
            "module": self.MODULE_NAME,
            "mode": mode,
            "target": self.target,
            "results": all_results,
        }

        if recursion:
            result["recursion"] = {
                "enabled": True,
                "depth": recursion_depth,
            }

        if warnings:
            result["warnings"] = warnings

        # 저장 옵션 처리
        if save_to == "auto":
            saved_path = self.save_results(result)
            result["saved_path"] = str(saved_path)
        elif save_to:
            saved_path = self.save_results(result, output_path=save_to)
            result["saved_path"] = str(saved_path)

        return result

    # ---------- 명령어 조립 ----------
    def _compose_command(
        self,
        target_url: str,
        wordlist: str,
        output_file: str,
        mode: str,
        recursion: bool = False,
        recursion_depth: int = 2,
        **options,
    ) -> list:
        """ffuf 실행 커맨드 조립"""
        cmd = [
            str(self.ffuf_bin),
            "-u", target_url,
            "-w", wordlist,
            "-o", output_file,
            "-of", "json",
            "-s",
            "-t", str(options.get("threads", 100)),
        ]

        # 모드별 기본 필터
        if mode == "directory":
            cmd += ["-fc", options.get("filter_code", "404")]
        elif mode == "subdomain":
            cmd += ["-ac"]  # 와일드카드 DNS 자동 보정
            if "filter_size" in options:
                cmd += ["-fs", str(options["filter_size"])]

        # 재귀 (directory 모드만)
        if recursion and mode == "directory":
            cmd += ["-recursion"]
            cmd += ["-recursion-depth", str(recursion_depth)]

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
        """ffuf JSON 출력을 팀 공통 스키마로 정규화"""
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

    def _annotate_depth(self, results: list) -> list:
        """
        재귀 결과에 depth 필드 추가 + depth 순 정렬.
        AI가 디렉토리 구조를 트리로 이해하기 쉽게 한다.
        """
        target_path = urlparse(self.target).path.rstrip("/")
        target_depth = target_path.count("/") if target_path else 0

        for r in results:
            url_path = urlparse(r["url"]).path.rstrip("/")
            r["depth"] = max(1, url_path.count("/") - target_depth)

        results.sort(key=lambda x: (x.get("depth", 0), x["url"]))
        return results

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
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            host = urlparse(self.target).netloc or self.target
            safe_host = "".join(c if c.isalnum() or c in "-_" else "_" for c in host)
            mode = result.get("mode", "unknown")

            depth_suffix = ""
            if result.get("recursion", {}).get("enabled"):
                depth_suffix = f"_d{result['recursion']['depth']}"

            filename = f"fuzzer_{mode}_{safe_host}{depth_suffix}_{timestamp}.json"

            save_dir = self.base_dir / results_dir
            save_dir.mkdir(parents=True, exist_ok=True)
            save_path = save_dir / filename

        save_path.parent.mkdir(parents=True, exist_ok=True)

        with open(save_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        return save_path

    def _error(self, msg: str, mode: str) -> dict:
        """공통 에러 반환 포맷"""
        return {
            "status": "error",
            "module": self.MODULE_NAME,
            "mode": mode,
            "target": self.target,
            "results": [],
            "error": msg,
        }