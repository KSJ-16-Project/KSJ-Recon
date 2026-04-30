"""
K-Shield Jr. Recon 모듈 - Portable Fuzzer (Core 통합용)

Core 시스템에서 import하여 사용하는 순수 모듈.
인터랙티브 UI나 출력 로직은 별도 CLI 파일(fuzzer_cli.py)에 있다.

사용 예시:
    from fuzzer_module import AggressiveFuzzer

    fuzzer = AggressiveFuzzer("http://target.com")
    result = fuzzer.run_fuzz(
        mode="directory",
        difficulty=1,
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
        directory 모드:
        {
            "status": "ok" | "error",
            "module": "fuzzer_portable",
            "mode": "directory",
            "target": str,
            "timestamp": str,
            "results": [
                {
                    "url": str,
                    "status": int,
                    "length": int,
                    "risk": "HIGH" | "LOW",
                    "depth": int,   # recursion 사용 시만
                },
                ...
            ],
            "warnings": [str, ...],  # 옵션
            "error": str,            # 옵션
        }

        subdomain 모드:
        {
            "status": "ok" | "error",
            "module": "fuzzer_portable",
            "mode": "subdomain",
            "target": str,
            "timestamp": str,
            "results": [
                {
                    "host": str,
                    "status": int,
                    "length": int,
                    "schemes": ["http", "https"],
                },
                ...
            ],
            "warnings": [str, ...],  # 옵션
            "error": str,            # 옵션
        }
    """

    MODULE_NAME = "fuzzer_portable"

    # 난이도별 wordlist
    WORDLISTS = {
        "directory": {
            1: "raft-small-directories.txt",   # 이지: ~17,000개
            2: "raft-large-directories.txt",   # 하드: ~62,000개
        },
        "subdomain": {
            1: "subdomains-top1million-5000.txt",
            2: "subdomains-top1million-20000.txt",
        },
    }

    # 난이도별 실행 옵션
    OPTIONS = {
        1: {
            "wordlist_dir": "raft-small-directories.txt",
            "wordlist_sub": "subdomains-top1million-5000.txt",
            "threads": 40,
            "timeout_sec": 600,
            "subdomain_timeout_sec": 900,
            "depth": 0,
            "recursion": False,
        },
        2: {
            "wordlist_dir": "raft-large-directories.txt",
            "wordlist_sub": "subdomains-top1million-20000.txt",
            "threads": 60,
            "timeout_sec": 3600,
            "subdomain_timeout_sec": 7200,
            "depth": None,
            "recursion": True,
        }
    }

    # 위험도 판단 패턴
    HIGH_RISK = [
        ".git", ".env", "admin", "backup", "config",
        "database", "phpinfo", "swagger", ".DS_Store",
        "wp-admin", "phpmyadmin", "shell", "upload",
        "actuator", "graphql", "api/admin", "dump",
        ".ssh", "passwd", "shadow", "secret", "private",
        "token", "credential", "key", "password",
    ]

    def __init__(self, target: str):
        """
        :param target: 퍼징 대상 URL (예: http://example.com)
        """
        self.target = target.rstrip("/")
        self.base_dir = Path(__file__).resolve().parent
        self.ffuf_bin = self._get_binary_path()
        self._ensure_executable()

    # ---------- 바이너리 ----------
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

    # ---------- URL 빌더 ----------
    def _build_target_urls(self, mode: str, try_https: bool = True) -> list:
        """
        디렉토리 모드: [http(s)://target/FUZZ]
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

    # ---------- depth 자동 조절 ----------
    def _calc_depth(self, difficulty: int, spider_url_count: int) -> int:
        """
        하드 모드에서 Spider URL 개수에 따라 depth 자동 조절.
        요청 폭발 방지.
        """
        if difficulty == 1:
            return 0

        # 하드 모드
        if spider_url_count <= 5:
            return 2
        elif spider_url_count <= 15:
            return 1
        else:
            return 0   # URL 너무 많으면 depth 포기

    # ---------- 메인 실행 ----------
    def run_fuzz(
        self,
        mode: str = "directory",
        difficulty: int = 1,
        spider_url_count: int = 0,
        try_https: bool = True,
        save_to: str = None,
        verbose: bool = False,
        wordlist: str = None,
        **options,
    ) -> dict:
        """
        퍼징을 실행하고 정규화된 결과 dict를 반환한다.

        :param mode: "directory" | "subdomain"
        :param difficulty: 1(이지) | 2(하드)
        :param spider_url_count: Spider URL 개수 (depth 자동 조절용)
        :param try_https: 서브도메인 모드에서 https도 시도할지
        :param save_to: 결과 저장 경로
                        - None: 저장 안 함
                        - "auto": results/ 폴더에 자동 파일명 생성
                        - "경로/파일.json": 직접 지정
        :param verbose: True면 진행 상황 로그 출력
        :param wordlist: 직접 지정 시 사용 (None이면 난이도별 자동)
        :param options: ffuf 추가 옵션 (고급 사용자용)
        :return: 정규화된 결과 dict
        """
        if not self.ffuf_bin.exists():
            return self._error(f"엔진 없음: {self.ffuf_bin}", mode)

        # 난이도별 옵션 결정
        opts = self.OPTIONS.get(difficulty, self.OPTIONS[1])
        threads = options.get("threads", opts["threads"])

        # 서브도메인/디렉터리 timeout 분리
        if mode == "subdomain":
            timeout_sec = options.get("timeout_sec", opts["subdomain_timeout_sec"])
        else:
            timeout_sec = options.get("timeout_sec", opts["timeout_sec"])
        options.setdefault("timeout", 3)

        # depth 자동 조절
        recursion       = opts["recursion"] if mode == "directory" else False
        recursion_depth = self._calc_depth(difficulty, spider_url_count)
        if recursion_depth == 0:
            recursion = False

        # wordlist 결정
        if wordlist is None:
            wordlist = self.WORDLISTS[mode][difficulty]
        wordlist_path = self._resolve_wordlist(wordlist)
        if not wordlist_path.exists():
            return self._error(f"워드리스트 없음: {wordlist_path}", mode)

        target_urls = self._build_target_urls(mode, try_https=try_https)
        all_results = []
        warnings    = []

        for target_url in target_urls:
            output_file = Path(tempfile.gettempdir()) / f"ffuf_{uuid.uuid4().hex}.json"
            try:
                cmd = self._compose_command(
                    target_url=target_url,
                    wordlist=str(wordlist_path),
                    output_file=str(output_file),
                    mode=mode,
                    threads=threads,
                    recursion=recursion,
                    recursion_depth=recursion_depth,
                    **options,
                )

                if verbose:
                    tag = f"(재귀 depth={recursion_depth})" if recursion else ""
                    print(f"[fuzzer] {mode} 퍼징 {tag}: {target_url}")

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

                all_results.extend(self._parse_output(output_file, mode, recursion))

            finally:
                if output_file.exists():
                    output_file.unlink()

        # 서브도메인 중복 제거
        if mode == "subdomain":
            all_results = self._dedupe_subdomains(all_results)

        # 결과 조립
        result = {
            "status":    "ok",
            "module":    self.MODULE_NAME,
            "mode":      mode,
            "target":    self.target,
            "timestamp": datetime.now().isoformat(),
            "results":   all_results,
        }

        if warnings:
            result["warnings"] = warnings

        # 저장
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
        threads: int = 40,
        recursion: bool = False,
        recursion_depth: int = 0,
        **options,
    ) -> list:
        cmd = [
            str(self.ffuf_bin),
            "-u", target_url,
            "-w", wordlist,
            "-o", output_file,
            "-of", "json",
            "-s",
            "-t", str(threads),
        ]

        # 모드별 필터
        if mode == "directory":
            cmd += ["-fc", options.get("filter_code", "404")]
        elif mode == "subdomain":
            cmd += ["-ac"]
            if "filter_size" in options:
                cmd += ["-fs", str(options["filter_size"])]

        # 재귀
        if recursion and mode == "directory":
            cmd += ["-recursion", "-recursion-depth", str(recursion_depth)]

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

        cmd += list(options.get("custom_args", []))
        return cmd

    # ---------- 정규화 ----------
    def _parse_output(self, output_file: Path, mode: str, recursion: bool = False) -> list:
        """ffuf JSON 출력을 확정 스키마로 정규화"""
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

            if mode == "directory":
                entry = {
                    "url":    url,
                    "status": item.get("status", 0),
                    "length": item.get("length", 0),
                    "risk":   self._check_risk(url),
                }
                if recursion:
                    entry["depth"] = self._calc_url_depth(url)

            elif mode == "subdomain":
                parsed = urlparse(url)
                entry = {
                    "host":   parsed.netloc,
                    "status": item.get("status", 0),
                    "scheme": parsed.scheme,
                }

            normalized.append(entry)
        return normalized

    def _dedupe_subdomains(self, results: list) -> list:
        """같은 host의 http/https를 하나로 합치고 schemes 리스트로 보존"""
        merged = {}
        for r in results:
            host = r.get("host", "")
            if not host:
                continue
            if host not in merged:
                merged[host] = {
                    "host":    host,
                    "status":  r.get("status", 0),
                    "schemes": [r.get("scheme", "http")],
                }
            else:
                scheme = r.get("scheme")
                if scheme and scheme not in merged[host]["schemes"]:
                    merged[host]["schemes"].append(scheme)

        return list(merged.values())

    # ---------- 위험도 판단 ----------
    def _check_risk(self, url: str) -> str:
        url_lower = url.lower()
        for pattern in self.HIGH_RISK:
            if pattern in url_lower:
                return "HIGH"
        return "LOW"

    def _calc_url_depth(self, url: str) -> int:
        """URL의 디렉토리 깊이 계산"""
        target_path = urlparse(self.target).path.rstrip("/")
        url_path    = urlparse(url).path.rstrip("/")
        target_depth = target_path.count("/") if target_path else 0
        return max(1, url_path.count("/") - target_depth)

    # ---------- 결과 저장 ----------
    def save_results(
        self,
        result: dict,
        output_path: str = None,
        results_dir: str = "results",
    ) -> Path:
        if output_path:
            save_path = Path(output_path)
            if not save_path.is_absolute():
                save_path = self.base_dir / save_path
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            host      = urlparse(self.target).netloc or self.target
            safe_host = "".join(
                c if c.isalnum() or c in "-_" else "_" for c in host
            )
            mode      = result.get("mode", "unknown")
            filename  = f"fuzzer_{mode}.json"

            folder_name = f"{safe_host}_{timestamp}"
            save_dir = self.base_dir / results_dir / folder_name
            save_dir.mkdir(parents=True, exist_ok=True)
            save_path = save_dir / filename

        save_path.parent.mkdir(parents=True, exist_ok=True)
        with open(save_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        return save_path

    def _error(self, msg: str, mode: str) -> dict:
        return {
            "status":    "error",
            "module":    self.MODULE_NAME,
            "mode":      mode,
            "target":    self.target,
            "timestamp": datetime.now().isoformat(),
            "results":   [],
            "error":     msg,
        }