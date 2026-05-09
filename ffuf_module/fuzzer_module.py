"""
K-Shield Jr. Recon 모듈 - Portable Fuzzer (Core 통합용)

Core 시스템에서 import하여 사용하는 순수 모듈.
인터랙티브 UI나 출력 로직은 별도 CLI 파일(fuzzer_cli.py)에 있다.

사용 예시:
    from fuzzer_module import FuzzOrchestrator

    result = FuzzOrchestrator().run(
        base_url    = "https://target.com",
        spider_urls = ["https://target.com/api"],
        difficulty  = 1,
        verbose     = True,
    )
    # result["results"] 사용
"""

import subprocess
import json
import os
import platform
import tempfile
import uuid
import re
import logging
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time


__all__ = ["FuzzOrchestrator", "AggressiveFuzzer"]

logger = logging.getLogger(__name__)

def _normalise_fuzz_target(url: str) -> str:
    """퍼징 대상 URL 정규화.
    - 쿼리 파라미터 제거 (?id=1 등)
    - 파일 URL이면 부모 디렉터리로 변환 (login.php → 상위 경로)
    """
    p = urlparse(url)
    path = p.path.rstrip("/") or "/"
    last_seg = path.rsplit("/", 1)[-1]
    _, ext = os.path.splitext(last_seg)
    if ext:
        path = path.rsplit("/", 1)[0] or "/"
    return f"{p.scheme}://{p.netloc}{path}".rstrip("/")


def _enable_verbose():
    """verbose 모드 시 모듈 logger에 stderr 핸들러 부착 (멱등)."""
    if not any(getattr(h, "_fuzzer_default", False) for h in logger.handlers):
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter("%(message)s"))
        h._fuzzer_default = True
        logger.addHandler(h)
    logger.setLevel(logging.INFO)


class AggressiveFuzzer:
    """
    번들링된 ffuf 바이너리로 디렉토리 퍼징을 수행하고,
    AI 파이프라인용 정규화 스키마로 결과를 반환한다.

    공통 반환 스키마:
    {
        "status":    "ok" | "error",
        "module":    "fuzzer_portable",
        "mode":      "directory",
        "target":    str,
        "timestamp": str,
        "results": [
            {
                "url":    str,
                "status": int,
                "length": int,
                "risk":   "HIGH" | "LOW",
                "depth":  int,    # recursion 사용 시만
            },
            ...
        ],
        "warnings": [str, ...],   # 옵션
        "error":    str,          # 옵션
    }
    """

    MODULE_NAME = "fuzzer_portable"

    # 난이도별 wordlist
    WORDLISTS = {
        1: "raft-small-words-lowercase.txt",   # 이지: ~17,000개
        2: "raft-large-words-lowercase.txt",   # 하드: ~62,000개
    }

    # 난이도별 실행 옵션
    OPTIONS = {
        1: {
            "threads": 40,
            "timeout_sec": 600,
            "depth": 0,
            "recursion": False,
        },
        2: {
            "threads": 60,
            "timeout_sec": 7200,
            "depth": 1,
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

    def __init__(self, base_dir=None):
        """
        :param base_dir: bin/, wordlists/, results/ 등의 베이스 경로
                         (기본값: 이 파일이 있는 디렉토리)
        target은 stateless하게 run_fuzz()에 매번 전달받음 (스레드 안전).
        """
        self.base_dir = Path(base_dir) if base_dir else Path(__file__).resolve().parent
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
            try:
                os.chmod(self.ffuf_bin, 0o755)
            except OSError as e:
                logger.warning(f"바이너리 실행 권한 부여 실패: {e}")

    def _resolve_wordlist(self, wordlist: str) -> Path:
        """절대경로면 그대로, 아니면 wordlists/ 디렉토리에서 탐색"""
        p = Path(wordlist)
        if p.is_absolute():
            return p
        return self.base_dir / "wordlists" / wordlist

    # ---------- depth 결정 ----------
    def _calc_depth(self, difficulty: int) -> int:
        """
        난이도별 고정 depth 반환.
        easy(1): 0  → 재귀 없음
        hard(2): 1  → 한 단계 더 재귀
        """
        return self.OPTIONS.get(difficulty, self.OPTIONS[1]).get("depth", 0)

    # ---------- 메인 실행 ----------
    def run_fuzz(
        self,
        target: str,
        difficulty: int = 1,
        save_to: str = None,
        verbose: bool = False,
        wordlist: str = None,
        progress_dict: dict = None,
        exclude_words: set = None,
        **options,
    ) -> dict:
        """
        퍼징을 실행하고 정규화된 결과 dict를 반환한다.

        :param target: 퍼징 대상 URL (예: http://example.com)
        :param difficulty: 1(이지) | 2(하드)
        :param save_to: 결과 저장 경로
                        - None: 저장 안 함
                        - "auto": results/ 폴더에 자동 파일명 생성
                        - "경로/파일.json": 직접 지정
        :param verbose: True면 진행 상황 로그 출력
        :param wordlist: 직접 지정 시 사용 (None이면 난이도별 자동)
        :param progress_dict: 외부 스레드와 진행률 공유용 dict (내부용)
        :param exclude_words: wordlist에서 제외할 단어 set (내부용)
        :param options: ffuf 추가 옵션 (filter_size, match_code, extensions,
                        timeout, proxy, headers, custom_args 등)
        :return: 정규화된 결과 dict
        """
        if verbose:
            _enable_verbose()

        target = _normalise_fuzz_target(target.rstrip("/"))

        if not self.ffuf_bin.exists():
            return self._error(target, f"엔진 없음: {self.ffuf_bin}")

        # 난이도별 옵션 결정
        opts        = self.OPTIONS.get(difficulty, self.OPTIONS[1])
        threads     = options.get("threads", opts["threads"])
        timeout_sec = options.get("timeout_sec", opts["timeout_sec"])
        options.setdefault("timeout", 3)

        # 재귀 결정
        recursion       = opts["recursion"]
        recursion_depth = self._calc_depth(difficulty)
        if recursion_depth == 0:
            recursion = False

        # wordlist 결정
        if wordlist is None:
            wordlist = self.WORDLISTS[difficulty]
        wordlist_path = self._resolve_wordlist(wordlist)
        if not wordlist_path.exists():
            return self._error(target, f"워드리스트 없음: {wordlist_path}")

        # 알려진 경로 제외한 임시 wordlist 생성 (실패 시 원본 사용)
        tmp_wordlist = None
        if exclude_words:
            tmp_wordlist = self._make_filtered_wordlist(wordlist_path, exclude_words)
            if tmp_wordlist:
                wordlist_path = tmp_wordlist

        target_url  = f"{target}/FUZZ"
        all_results = []
        warnings    = []
        output_file = Path(tempfile.gettempdir()) / f"ffuf_{uuid.uuid4().hex}.json"
        proc        = None

        try:
            cmd = self._compose_command(
                target_url      = target_url,
                wordlist        = str(wordlist_path),
                output_file     = str(output_file),
                threads         = threads,
                recursion       = recursion,
                recursion_depth = recursion_depth,
                **options,
            )

            tag = f"(재귀 depth={recursion_depth})" if recursion else ""
            logger.info(f"[fuzzer] directory 퍼징 {tag}: {target_url}")

            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout = subprocess.DEVNULL,
                    stderr = subprocess.PIPE,
                    text   = True,
                )
                tracker = threading.Thread(
                    target = self._track_progress,
                    args   = (proc, progress_dict),
                    daemon = True,
                )
                tracker.start()
                try:
                    proc.wait(timeout=timeout_sec)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                    warnings.append(f"타임아웃: {target_url}")
                tracker.join(timeout=5)
            except FileNotFoundError as e:
                warnings.append(f"바이너리 실행 실패: {e}")
                logger.error(f"ffuf 바이너리 실행 실패 ({target}): {e}")
            except OSError as e:
                warnings.append(f"실행 오류: {e}")
                logger.error(f"실행 오류 ({target}): {e}")

            # ffuf가 부분이라도 출력했으면 파싱
            all_results.extend(self._parse_output(target, output_file, recursion))

        except KeyboardInterrupt:
            # 진행 중이던 ffuf 프로세스 강제 종료
            if proc is not None and proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(timeout=5)
                except Exception:
                    pass
            warnings.append(f"사용자 중단: {target_url}")
            logger.warning(f"사용자 중단: {target_url}")
            # 부분 결과라도 회수 시도
            try:
                all_results.extend(self._parse_output(target, output_file, recursion))
            except Exception:
                pass
            raise
        except Exception as e:
            logger.error(f"퍼징 중 예상치 못한 오류 ({target}): {e}")
            warnings.append(f"예상치 못한 오류: {e}")
        finally:
            try:
                if output_file.exists():
                    output_file.unlink()
            except OSError:
                pass
            try:
                if tmp_wordlist and tmp_wordlist.exists():
                    tmp_wordlist.unlink()
            except OSError:
                pass

        # ffuf 재귀 실행 시 같은 URL이 중복 추가될 수 있어 dedup
        seen   = set()
        unique = []
        for item in all_results:
            key = item.get("url")
            if key and key not in seen:
                seen.add(key)
                unique.append(item)
        all_results = unique

        # 결과 조립
        result = {
            "status":    "ok",
            "module":    self.MODULE_NAME,
            "mode":      "directory",
            "target":    target,
            "timestamp": datetime.now().isoformat(),
            "results":   all_results,
        }

        if warnings:
            result["warnings"] = warnings

        # 저장 (실패 시 saved_path 누락, 데이터는 결과 dict에 그대로)
        if save_to == "auto":
            saved_path = self.save_results(result)
            if saved_path:
                result["saved_path"] = str(saved_path)
        elif save_to:
            saved_path = self.save_results(result, output_path=save_to)
            if saved_path:
                result["saved_path"] = str(saved_path)

        return result

    # ---------- wordlist 필터링 ----------
    def _make_filtered_wordlist(self, wordlist_path: Path, exclude_words: set):
        """알려진 경로를 제외한 임시 wordlist 파일 생성. 실패 시 None 반환"""
        tmp = Path(tempfile.gettempdir()) / f"ffuf_wl_{uuid.uuid4().hex}.txt"
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as fin, \
                 open(tmp, 'w', encoding='utf-8') as fout:
                for line in fin:
                    if line.strip() not in exclude_words:
                        fout.write(line)
            return tmp
        except OSError as e:
            logger.warning(f"wordlist 필터링 실패, 원본 사용: {e}")
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass
            return None

    # ---------- 진행률 추적 ----------
    def _track_progress(self, proc, progress_dict: dict):
        """ffuf stderr에서 진행률을 파싱하여 progress_dict에 업데이트.
        재귀 실행 시 Job [X/Y] 기준으로 누적 % 계산.
        """
        prog_pat = re.compile(r'Progress: \[(\d+)/(\d+)\]')
        job_pat  = re.compile(r'Job \[(\d+)/(\d+)\]')
        try:
            for line in proc.stderr:
                if progress_dict is None:
                    continue
                prog_m = prog_pat.search(line)
                if not prog_m:
                    continue
                cur, tot = int(prog_m.group(1)), int(prog_m.group(2))
                if tot <= 0:
                    continue
                job_m = job_pat.search(line)
                if job_m:
                    job_cur, job_tot = int(job_m.group(1)), int(job_m.group(2))
                    pct = int((job_cur - 1 + cur / tot) / job_tot * 100)
                else:
                    pct = int(cur / tot * 100)
                progress_dict['pct'] = pct
                progress_dict['cur'] = cur
                progress_dict['tot'] = tot
        except Exception as e:
            logger.debug(f"진행률 추적 오류: {e}")

    # ---------- 명령어 조립 ----------
    def _compose_command(
        self,
        target_url:      str,
        wordlist:        str,
        output_file:     str,
        threads:         int  = 40,
        recursion:       bool = False,
        recursion_depth: int  = 0,
        **options,
    ) -> list:
        cmd = [
            str(self.ffuf_bin),
            "-u", target_url,
            "-w", wordlist,
            "-o", output_file,
            "-of", "json",
            "-t", str(threads),
            "-ac",   # auto-calibration: wildcard 응답 자동 필터
        ]

        if "filter_size" in options:
            cmd += ["-fs", str(options["filter_size"])]

        # 재귀
        if recursion:
            cmd += ["-recursion", "-recursion-depth", str(recursion_depth)]

        # 공통 옵션
        if "match_code" in options:
            cmd += ["-mc", options["match_code"]]
        if "extensions" in options:
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
    def _parse_output(self, target: str, output_file: Path, recursion: bool = False) -> list:
        """ffuf JSON 출력을 확정 스키마로 정규화"""
        if not output_file.exists() or output_file.stat().st_size == 0:
            return []
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except json.JSONDecodeError as e:
            logger.warning(f"ffuf JSON 파싱 실패: {output_file} - {e}")
            return []

        normalized = []
        for item in raw.get("results", []):
            url   = item.get("url", "")
            entry = {
                "url":    url,
                "status": item.get("status", 0),
                "length": item.get("length", 0),
                "risk":   self._check_risk(url),
            }
            if recursion:
                entry["depth"] = self._calc_url_depth(target, url)
            normalized.append(entry)
        return normalized

    # ---------- 위험도 판단 ----------
    def _check_risk(self, url: str) -> str:
        url_lower = url.lower()
        for pattern in self.HIGH_RISK:
            if pattern in url_lower:
                return "HIGH"
        return "LOW"

    def _calc_url_depth(self, target: str, url: str) -> int:
        """URL의 디렉토리 깊이 계산"""
        target_path  = urlparse(target).path.rstrip("/")
        url_path     = urlparse(url).path.rstrip("/")
        target_depth = target_path.count("/") if target_path else 0
        return max(1, url_path.count("/") - target_depth)

    # ---------- 결과 저장 ----------
    def save_results(
        self,
        result:      dict,
        output_path: str = None,
        results_dir: str = "results",
    ):
        """결과를 JSON으로 저장. 실패 시 None 반환"""
        try:
            if output_path:
                save_path = Path(output_path)
                if not save_path.is_absolute():
                    save_path = self.base_dir / save_path
            else:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                target    = result.get("target", "")
                host      = urlparse(target).netloc or target
                safe_host = "".join(
                    c if c.isalnum() or c in "-_" else "_" for c in host
                )
                filename  = "fuzzer_directory.json"

                folder_name = f"{safe_host}_{timestamp}"
                save_dir    = self.base_dir / results_dir / folder_name
                save_dir.mkdir(parents=True, exist_ok=True)
                save_path   = save_dir / filename

            save_path.parent.mkdir(parents=True, exist_ok=True)
            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)

            return save_path
        except OSError as e:
            logger.warning(f"결과 저장 실패: {e}")
            return None

    def _error(self, target: str, msg: str) -> dict:
        return {
            "status":    "error",
            "module":    self.MODULE_NAME,
            "mode":      "directory",
            "target":    target,
            "timestamp": datetime.now().isoformat(),
            "results":   [],
            "error":     msg,
        }


class FuzzOrchestrator:
    """
    base_url과 spider_urls를 묶어서 병렬로 퍼징을 실행하고
    결과를 통합해서 반환하는 상위 레벨 조정자.

    Core 시스템 통합 시 보통 이 클래스를 사용한다.
    """

    def __init__(self, base_dir=None):
        """
        :param base_dir: bin/, wordlists/, results/ 등의 베이스 경로
                         (기본값: 이 파일이 있는 디렉토리)
        """
        self.base_dir = Path(base_dir) if base_dir else Path(__file__).resolve().parent
        # AggressiveFuzzer는 stateless하므로 인스턴스 1개를 모든 태스크가 공유
        self.fuzzer = AggressiveFuzzer(base_dir=self.base_dir)

    def run(
        self,
        base_url:    str,
        spider_urls: list,
        difficulty:  int,
        run_dir:     str  = None,
        verbose:     bool = False,
    ) -> dict:
        """
        base_url과 spider_urls를 병렬 퍼징 실행.

        :param base_url: 루트 퍼징 대상 (예: "https://target.com")
        :param spider_urls: Spider가 발견한 URL 목록 ([] 가능)
        :param difficulty: 1(이지) | 2(하드)
        :param run_dir: 결과 저장 폴더 (None이면 results/{host}_{timestamp}/ 자동 생성)
        :param verbose: True면 진행 로그 출력

        :return: {
            "status":      "ok",
            "base_url":    str,
            "tld1":        str,
            "difficulty":  int,
            "spider_urls": list,
            "timestamp":   str,
            "run_dir":     str,
            "results":     [태스크별 결과 dict, ...],
        }
        """
        if verbose:
            _enable_verbose()

        host = urlparse(base_url).netloc or base_url
        host = host.split(":")[0]
        tld1 = ".".join(host.split(".")[-2:]) if "." in host else host

        # 디렉토리 준비 실패 시 즉시 에러 응답
        try:
            run_dir = self._prepare_run_dir(base_url, run_dir)
        except RuntimeError as e:
            logger.error(str(e))
            return self._build_response(
                status="error", base_url=base_url, tld1=tld1,
                difficulty=difficulty, spider_urls=spider_urls,
                run_dir="", all_results=[], error=str(e),
            )

        exclude_words = self._compute_exclude_words(base_url, spider_urls)
        all_tasks     = self._build_tasks(base_url, spider_urls)
        all_results   = [None] * len(all_tasks)

        try:
            self._execute_tasks(
                all_tasks, run_dir, difficulty, verbose, exclude_words, all_results,
            )
            self._dedupe_across_tasks(all_results)
            return self._build_response(
                status="ok", base_url=base_url, tld1=tld1,
                difficulty=difficulty, spider_urls=spider_urls,
                run_dir=str(run_dir), all_results=all_results,
            )
        except KeyboardInterrupt:
            logger.warning("사용자가 중단했습니다 - 부분 결과 반환")
            # 취소된 태스크의 None 슬롯을 에러 dict로 채움
            for i, (url, _) in enumerate(all_tasks):
                if all_results[i] is None:
                    all_results[i] = self.fuzzer._error(url, "사용자 중단으로 취소됨")
            self._dedupe_across_tasks(all_results)
            return self._build_response(
                status="interrupted", base_url=base_url, tld1=tld1,
                difficulty=difficulty, spider_urls=spider_urls,
                run_dir=str(run_dir), all_results=all_results,
            )
        except Exception as e:
            logger.error(f"퍼징 실행 중 예상치 못한 오류: {e}")
            return self._build_response(
                status="error", base_url=base_url, tld1=tld1,
                difficulty=difficulty, spider_urls=spider_urls,
                run_dir=str(run_dir), all_results=all_results, error=str(e),
            )

    def _build_response(
        self,
        status:      str,
        base_url:    str,
        tld1:        str,
        difficulty:  int,
        spider_urls: list,
        run_dir:     str,
        all_results: list,
        error:       str = None,
    ) -> dict:
        """run() 응답 dict 빌더"""
        resp = {
            "status":      status,
            "base_url":    base_url,
            "tld1":        tld1,
            "difficulty":  difficulty,
            "spider_urls": spider_urls,
            "timestamp":   datetime.now().isoformat(),
            "run_dir":     run_dir,
            "results":     all_results,
        }
        if error:
            resp["error"] = error
        return resp

    # ---------- 디렉토리 준비 ----------
    def _prepare_run_dir(self, base_url: str, run_dir: str = None) -> Path:
        """결과 저장용 run_dir 결정 및 생성"""
        try:
            results_dir = self.base_dir / "results"
            results_dir.mkdir(exist_ok=True)

            if run_dir is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                host      = urlparse(base_url).netloc or base_url
                safe_host = "".join(c if c.isalnum() or c in "-_" else "_" for c in host)
                run_dir   = results_dir / f"{safe_host}_{timestamp}"
            run_dir = Path(run_dir)
            run_dir.mkdir(parents=True, exist_ok=True)
            return run_dir
        except OSError as e:
            raise RuntimeError(f"결과 디렉토리 생성 실패 ({run_dir}): {e}") from e

    # ---------- exclude_words 계산 ----------
    def _compute_exclude_words(self, base_url: str, spider_urls: list) -> set:
        """spider_urls에서 base_url 직계 하위 경로를 추출해 wordlist 제외 단어로 사용"""
        parsed_base = urlparse(base_url)
        base_path   = parsed_base.path.rstrip("/")
        base_netloc = parsed_base.netloc

        exclude_words = set()
        for url in spider_urls:
            p = urlparse(url)
            if p.netloc != base_netloc:
                continue
            url_path = p.path.rstrip("/")
            prefix   = base_path + "/"
            if url_path.startswith(prefix):
                first_seg = url_path[len(base_path):].lstrip("/").split("/")[0]
                if first_seg:
                    exclude_words.add(first_seg)

        if exclude_words:
            logger.info(f"  [최적화] base_url 퍼징에서 {len(exclude_words)}개 알려진 경로 제외: {', '.join(sorted(exclude_words))}")

        return exclude_words

    # ---------- 태스크 빌드 ----------
    def _build_tasks(self, base_url: str, spider_urls: list) -> list:
        """(url, filename) 튜플 리스트 생성.
        spider_urls는 정규화(쿼리 제거·파일→부모 디렉터리) 후 중복 제거."""
        seen = {base_url}
        spider_tasks = []
        for url in spider_urls:
            normalised = _normalise_fuzz_target(url)
            if normalised not in seen:
                seen.add(normalised)
                spider_tasks.append((normalised, f"fuzzer_spider_{len(spider_tasks) + 1}.json"))
        return [(base_url, "fuzzer_directory.json")] + spider_tasks

    # ---------- 단일 태스크 실행 ----------
    def _run_single_task(
        self,
        idx:           int,
        url:           str,
        filename:      str,
        run_dir:       Path,
        difficulty:    int,
        verbose:       bool,
        exclude_words: set,
        progress_dict: dict,
    ) -> dict:
        """ThreadPool에서 호출되는 워커. 단일 ffuf 퍼징 실행"""
        kwargs = dict(
            difficulty    = difficulty,
            save_to       = str(run_dir / filename),
            verbose       = verbose,
            progress_dict = progress_dict,
        )
        # base_url 태스크(idx=0)에만 알려진 경로 제외 적용
        if idx == 0 and exclude_words:
            kwargs["exclude_words"] = exclude_words
        return self.fuzzer.run_fuzz(target=url, **kwargs)

    # ---------- 진행 모니터링 ----------
    def _monitor_progress(self, stop_event, task_status: dict, task_progress: list):
        """30초마다 실행 중인 태스크의 진행률을 logger에 출력"""
        while not stop_event.is_set():
            time.sleep(30)
            if stop_event.is_set():
                break
            for i, s in task_status.items():
                if s["start"] and not s["done"]:
                    elapsed = int(time.time() - s["start"])
                    m, sec  = divmod(elapsed, 60)
                    pct     = task_progress[i].get("pct", 0)
                    logger.info(f"  [진행중] {s['url']} ({m}분 {sec}초 경과) {pct}%")

    # ---------- ThreadPool 실행 ----------
    def _execute_tasks(
        self,
        all_tasks:     list,
        run_dir:       Path,
        difficulty:    int,
        verbose:       bool,
        exclude_words: set,
        all_results:   list,
    ) -> None:
        """모든 태스크를 병렬 실행하고 all_results에 in-place로 채워 넣음.
        KeyboardInterrupt 발생 시 부분 결과만 채워진 채로 예외 재전파."""
        task_progress = [{} for _ in all_tasks]
        task_status   = {
            i: {"url": url, "start": None, "done": False}
            for i, (url, _) in enumerate(all_tasks)
        }

        stop_event     = threading.Event()
        monitor_thread = threading.Thread(
            target = self._monitor_progress,
            args   = (stop_event, task_status, task_progress),
            daemon = True,
        )
        monitor_thread.start()

        try:
            with ThreadPoolExecutor(max_workers=min(len(all_tasks), 4)) as executor:
                futures = {}
                for i, (url, fname) in enumerate(all_tasks):
                    task_status[i]["start"] = time.time()
                    futures[executor.submit(
                        self._run_single_task,
                        i, url, fname, run_dir, difficulty, verbose,
                        exclude_words, task_progress[i],
                    )] = i

                try:
                    for future in as_completed(futures):
                        idx = futures[future]
                        try:
                            result = future.result()
                        except Exception as e:
                            logger.error(f"태스크 실행 실패 (idx={idx}): {e}")
                            url    = task_status[idx]["url"]
                            result = self.fuzzer._error(url, f"태스크 실행 실패: {e}")
                        all_results[idx] = result
                        s         = task_status[idx]
                        s["done"] = True
                        elapsed   = int(time.time() - s["start"])
                        m, sec    = divmod(elapsed, 60)
                        count     = len(result.get("results", []))
                        logger.info(f"  [완료] {s['url']} → {count}개 발견 ({m}분 {sec}초)")
                except KeyboardInterrupt:
                    logger.warning("사용자 중단 감지 - 진행 중인 태스크 취소 시도")
                    for f in futures:
                        f.cancel()
                    raise
        finally:
            stop_event.set()
            if monitor_thread.is_alive():
                monitor_thread.join(timeout=2)

    # ---------- 태스크간 중복 제거 ----------
    def _dedupe_across_tasks(self, all_results: list) -> None:
        """여러 태스크 결과 중 URL 중복 제거 (in-place)"""
        seen        = set()
        dedup_count = 0
        for result in all_results:
            if not result:
                continue
            unique = []
            for item in result.get("results", []):
                key = item.get("url")
                if key and key not in seen:
                    seen.add(key)
                    unique.append(item)
                else:
                    dedup_count += 1
            result["results"] = unique

        if dedup_count > 0:
            logger.info(f"  [중복 제거] {dedup_count}개 항목 제거됨")
