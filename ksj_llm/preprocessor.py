import os
import json
import re
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from dotenv import load_dotenv
import anthropic


class LLMPreprocessor:
    def __init__(self):
        # claude/preprocessor_llm.py 기준 project 루트 계산
        self.base_dir = Path(__file__).resolve().parent.parent

        # project/.env 로드
        load_dotenv(self.base_dir / ".env", override=True)
        load_dotenv()

        self.api_key = os.getenv("ANTHROPIC_API_KEY")
        self.model = os.getenv("PREPROCESS_MODEL_NAME") or os.getenv("MODEL_NAME")

        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY가 설정되지 않았습니다.")

        if not self.model:
            raise ValueError("PREPROCESS_MODEL_NAME 또는 MODEL_NAME이 설정되지 않았습니다.")

        self.api_key = self.api_key.strip()
        self.model = self.model.strip()

        self.client = anthropic.Anthropic(api_key=self.api_key)

    def load_prompt_template(self):
        prompt_path = self.base_dir / "prompts" / "preprocess_prompt.txt"

        if not prompt_path.exists():
            raise FileNotFoundError(f"전처리 프롬프트 파일을 찾을 수 없습니다: {prompt_path}")

        with open(prompt_path, "r", encoding="utf-8") as f:
            return f.read()

    def make_json_safe(self, obj):
        """
        PageSnapshot 같은 JSON 직렬화 불가능한 객체가 들어와도
        LLM에 넘길 수 있도록 dict/list/string 형태로 변환
        """
        if isinstance(obj, dict):
            return {str(k): self.make_json_safe(v) for k, v in obj.items()}

        if isinstance(obj, list):
            return [self.make_json_safe(v) for v in obj]

        if isinstance(obj, tuple):
            return [self.make_json_safe(v) for v in obj]

        if isinstance(obj, (str, int, float, bool)) or obj is None:
            return obj

        if hasattr(obj, "model_dump"):
            return self.make_json_safe(obj.model_dump())

        if hasattr(obj, "dict"):
            return self.make_json_safe(obj.dict())

        if hasattr(obj, "__dict__"):
            return self.make_json_safe(vars(obj))

        return str(obj)

    def extract_query_params(self, urls):
        """
        URL 문자열에 포함된 query parameter를 동적으로 추출
        파라미터명은 고정하지 않고 실제 URL 기준으로 수집
        """
        extracted = []
        seen = set()

        for url in urls:
            if not isinstance(url, str) or "?" not in url:
                continue

            parsed = urlparse(url)
            parsed_params = parse_qs(parsed.query, keep_blank_values=True)

            if not parsed_params:
                continue

            params = {
                name: values[0] if len(values) == 1 else values
                for name, values in parsed_params.items()
            }
            key = (url, json.dumps(params, sort_keys=True, ensure_ascii=False))

            if key in seen:
                continue

            seen.add(key)
            extracted.append({
                "url": url,
                "params": params
            })

        return extracted

    def safe_list(self, value):
        return value if isinstance(value, list) else []

    def minimize_scan_data(self, scan_data: dict):
        """
        LLM 전처리에 필요한 핵심 필드만 남겨 입력 토큰을 줄임
        raw_html/rendered_html/saved_path 같은 대용량 필드는 제외
        """
        crawler = scan_data.get("crawler") or {}
        fuzzer = scan_data.get("fuzzer") or {}
        nmap = scan_data.get("nmap") or {}

        pages = []
        query_source_urls = []
        for page in self.safe_list(crawler.get("public_pages")):
            page = page if isinstance(page, dict) else {}
            response_headers = page.get("response_headers") or {}
            page_urls = [
                page.get("url"),
                *self.safe_list(page.get("links")),
                *self.safe_list(page.get("routes")),
                *self.safe_list(page.get("xhr_list")),
                *self.safe_list(page.get("ws_list")),
                *self.safe_list(page.get("endpoint_hints"))
            ]
            query_source_urls.extend(page_urls)
            pages.append({
                "url": page.get("url"),
                "status": page.get("status"),
                "links": self.safe_list(page.get("links")),
                "routes": self.safe_list(page.get("routes")),
                "forms": self.safe_list(page.get("forms")),
                "technologies": self.safe_list(page.get("technologies")),
                "render_type": page.get("render_type"),
                "xhr_list": self.safe_list(page.get("xhr_list")),
                "ws_list": self.safe_list(page.get("ws_list")),
                "endpoint_hints": self.safe_list(page.get("endpoint_hints")),
                "cookies": self.safe_list(page.get("cookies")),
                "response_headers": {
                    "server": response_headers.get("server"),
                    "set-cookie": response_headers.get("set-cookie"),
                    "content-type": response_headers.get("content-type")
                }
            })

        authenticated_pages = []
        for page in self.safe_list(crawler.get("authenticated_pages")):
            page = page if isinstance(page, dict) else {}
            response_headers = page.get("response_headers") or {}
            page_urls = [
                page.get("url"),
                *self.safe_list(page.get("links")),
                *self.safe_list(page.get("routes")),
                *self.safe_list(page.get("xhr_list")),
                *self.safe_list(page.get("ws_list")),
                *self.safe_list(page.get("endpoint_hints"))
            ]
            query_source_urls.extend(page_urls)
            authenticated_pages.append({
                "url": page.get("url"),
                "status": page.get("status"),
                "links": self.safe_list(page.get("links")),
                "routes": self.safe_list(page.get("routes")),
                "forms": self.safe_list(page.get("forms")),
                "xhr_list": self.safe_list(page.get("xhr_list")),
                "ws_list": self.safe_list(page.get("ws_list")),
                "endpoint_hints": self.safe_list(page.get("endpoint_hints")),
                "cookies": self.safe_list(page.get("cookies")),
                "response_headers": {
                    "server": response_headers.get("server"),
                    "set-cookie": response_headers.get("set-cookie"),
                    "content-type": response_headers.get("content-type")
                }
            })

        fuzzer_results = []
        for group in self.safe_list(fuzzer.get("results")):
            group = group if isinstance(group, dict) else {}
            for item in self.safe_list(group.get("results")):
                item = item if isinstance(item, dict) else {}
                fuzzer_results.append({
                    "url": item.get("url"),
                    "status": item.get("status"),
                    "length": item.get("length"),
                    "risk": item.get("risk")
                })
                query_source_urls.append(item.get("url"))

        ports = []
        for host in self.safe_list(nmap.get("hosts")):
            host = host if isinstance(host, dict) else {}
            for port in self.safe_list(host.get("ports")):
                port = port if isinstance(port, dict) else {}
                ports.append({
                    "port": port.get("port"),
                    "protocol": port.get("protocol"),
                    "state": port.get("state"),
                    "service": port.get("service"),
                    "product": port.get("product"),
                    "version": port.get("version"),
                    "extra_info": port.get("extra_info")
                })

        robots_info = crawler.get("robots_info") or {}

        return {
            "nmap": {
                "target": nmap.get("target"),
                "hosts": [
                    {
                        "ip": host.get("ip"),
                        "status": host.get("status")
                    }
                    for host in self.safe_list(nmap.get("hosts"))
                    if isinstance(host, dict)
                ],
                "ports": ports
            },
            "crawler": {
                "target_url": crawler.get("target_url"),
                "public_pages": pages,
                "authenticated_pages": authenticated_pages,
                "query_params": self.extract_query_params(query_source_urls),
                "auth": crawler.get("auth"),
                "sitemap_urls": self.safe_list(crawler.get("sitemap_urls")),
                "robots_info": {
                    "disallowed": self.safe_list(robots_info.get("disallowed")),
                    "sitemaps": self.safe_list(robots_info.get("sitemaps"))
                },
                "endpoint_hints": self.safe_list(crawler.get("endpoint_hints")),
                "errors": self.safe_list(crawler.get("errors"))
            },
            "fuzzer": {
                "base_url": fuzzer.get("base_url"),
                "spider_urls": self.safe_list(fuzzer.get("spider_urls")),
                "results": fuzzer_results
            }
        }

    def build_prompt(self, scan_data: dict):
        prompt_template = self.load_prompt_template()

        safe_scan_data = self.make_json_safe(scan_data)
        minimal_scan_data = self.minimize_scan_data(safe_scan_data)

        combined_data = json.dumps(
            minimal_scan_data,
            ensure_ascii=False,
            separators=(",", ":")
        )

        json_output_rule = """
[Final Output Rules / STRICT JSON OUTPUT]
Return only one valid JSON object.
Do not output markdown, explanations, code fences, or comments.
Follow strict JSON syntax.
Do not add trailing commas after the last item in an object or array.
Wrap every JSON key and every string value in double quotes.
Use pure JSON syntax, not Python dict syntax.
Use null, true, and false instead of None, True, and False.
Keep JSON keys and enum values in English.
Write only human-readable explanation fields such as "reason" and "limitations" in Korean.
"""

        return f"{prompt_template}\n\n{json_output_rule}\n\n[Scan Data]\n{combined_data}"

    def parse_llm_json(self, response_text: str):
        text = response_text.strip()

        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text)
            text = re.sub(r"\s*```$", "", text)
            text = text.strip()

        # LLM이 실수로 붙인 trailing comma 제거
        text = re.sub(r",\s*([}\]])", r"\1", text)

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}")

            if start != -1 and end != -1 and start < end:
                candidate = text[start:end + 1]
                candidate = re.sub(r",\s*([}\]])", r"\1", candidate)

                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    pass

            raise ValueError("LLM 전처리 응답이 올바른 JSON 형식이 아닙니다.")

    def _as_dict(self, value):
        return value if isinstance(value, dict) else {}

    def _as_list(self, value):
        return value if isinstance(value, list) else []

    def _as_str(self, value):
        if value is None:
            return ""
        return value if isinstance(value, str) else str(value)

    def _as_bool(self, value, default=False):
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in ("true", "1", "yes", "y"):
                return True
            if normalized in ("false", "0", "no", "n"):
                return False
        if value is None:
            return default
        return bool(value)

    def _as_int(self, value, default=0):
        if isinstance(value, bool):
            return default
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _as_float(self, value, default=0.0):
        if isinstance(value, bool):
            return default
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    def _as_string_list(self, value):
        return [
            self._as_str(item)
            for item in self._as_list(value)
            if item is not None
        ]

    def _normalize_options(self, value, defaults):
        options = self._as_dict(value).copy()
        for key, default_value in defaults.items():
            current_value = options.get(key)
            if isinstance(default_value, bool):
                options[key] = self._as_bool(current_value, default_value)
            elif isinstance(default_value, int) and not isinstance(default_value, bool):
                options[key] = self._as_int(current_value, default_value)
            elif isinstance(default_value, float):
                options[key] = self._as_float(current_value, default_value)
            elif isinstance(default_value, dict):
                options[key] = self._as_dict(current_value)
            elif current_value is None:
                options[key] = default_value
        return options

    def _normalize_sql_param(self, item):
        param = self._as_dict(item).copy()
        param["name"] = self._as_str(param.get("name"))
        param["location"] = self._as_str(param.get("location") or "unknown")
        if param["location"] not in ("query", "body", "path", "header", "unknown"):
            param["location"] = "unknown"
        param["value"] = self._as_str(param.get("value"))
        return param

    def _normalize_xss_target(self, item):
        target = self._as_dict(item).copy()
        target["url"] = self._as_str(target.get("url"))
        target["method"] = self._as_str(target.get("method") or "GET").upper()
        if target["method"] not in ("GET", "POST"):
            target["method"] = "GET"
        target["body_format"] = self._as_str(target.get("body_format") or "unknown")
        if target["body_format"] not in ("form", "json", "raw", "unknown"):
            target["body_format"] = "unknown"
        target["params"] = self._as_dict(target.get("params"))
        target["check_urls"] = self._as_string_list(target.get("check_urls"))
        target["safe_to_submit"] = self._as_bool(target.get("safe_to_submit"), False)
        target["cookies"] = self._as_dict(target.get("cookies"))
        target["headers"] = self._as_dict(target.get("headers"))
        target["priority"] = self._as_str(target.get("priority") or "MEDIUM").upper()
        if target["priority"] not in ("HIGH", "MEDIUM", "LOW"):
            target["priority"] = "MEDIUM"
        target["reason"] = self._as_str(target.get("reason"))
        return target

    def _normalize_attack_target(self, item):
        target = self._as_dict(item).copy()
        target["url"] = self._as_str(target.get("url"))
        target["method"] = self._as_str(target.get("method") or "GET").upper()
        if target["method"] not in ("GET", "POST"):
            target["method"] = "GET"
        target["params"] = self._as_dict(target.get("params"))
        target["data"] = self._as_dict(target.get("data"))
        target["headers"] = self._as_dict(target.get("headers"))
        target["inject_params"] = self._as_string_list(target.get("inject_params"))
        try:
            target["timeout"] = float(target.get("timeout", 5.0))
        except (TypeError, ValueError):
            target["timeout"] = 5.0
        target["priority"] = self._as_str(target.get("priority") or "MEDIUM").upper()
        if target["priority"] not in ("HIGH", "MEDIUM", "LOW"):
            target["priority"] = "MEDIUM"
        target["reason"] = self._as_str(target.get("reason"))
        return target

    def normalize_preprocess_data(self, pre_data: dict):
        """
        LLM 응답이 일부 필드를 누락해도 후속 모듈이 같은 JSON 계약을 받도록 보정한다.
        후보를 새로 만들지는 않고, 기존 값의 타입과 기본 키만 정리한다.
        """
        pre_data = self._as_dict(pre_data)

        sql_data = self._as_dict(pre_data.get("sql_data")).copy()
        auth = self._as_dict(sql_data.get("auth")).copy()
        nmap_data = self._as_dict(sql_data.get("nmap_data")).copy()

        normalized = {
            "sql_data": {
                "target_url": self._as_str(sql_data.get("target_url")),
                "crawler_data": [
                    self._normalize_sql_param(item)
                    for item in self._as_list(sql_data.get("crawler_data"))
                ],
                "auth": {
                    "cookie": self._as_str(auth.get("cookie")),
                    "Authorization": self._as_str(auth.get("Authorization")),
                    "Referer": self._as_str(auth.get("Referer")),
                    "Accept-Language": self._as_str(auth.get("Accept-Language"))
                },
                "nmap_data": {
                    "port": self._as_str(nmap_data.get("port")),
                    "service": self._as_str(nmap_data.get("service")),
                    "version": self._as_str(nmap_data.get("version"))
                },
                "fuzzer_data": self._as_string_list(sql_data.get("fuzzer_data"))
            },
            "xss_data": {},
            "filedown_data": {},
            "ssrf_data": {},
            "limitations": self._as_list(pre_data.get("limitations"))
        }

        xss_data = self._as_dict(pre_data.get("xss_data")).copy()
        xss_options = {
            "browser_verify": True,
            "stored_xss": True,
            "dom_hash_xss": True,
            "dom_stored_xss": False,
            "timeout": 10,
            "verify_tls": False
        }
        normalized["xss_data"] = {
            "base_url": self._as_str(xss_data.get("base_url")),
            "session_id": self._as_str(xss_data.get("session_id")),
            "token": self._as_str(xss_data.get("token")),
            "login_mock_path": self._as_str(xss_data.get("login_mock_path")),
            "spider_urls": self._as_string_list(xss_data.get("spider_urls")),
            "stored_targets": [
                self._normalize_xss_target(item)
                for item in self._as_list(xss_data.get("stored_targets"))
            ],
            "options": self._normalize_options(xss_data.get("options"), xss_options),
            "evidence_dir": self._as_str(xss_data.get("evidence_dir") or "evidence"),
            "results_dir": self._as_str(xss_data.get("results_dir") or "results")
        }

        module_options = {
            "max_workers": 4,
            "payload_limit": 3,
            "timeout": 10.0,
            "verify": False,
            "allow_redirects": False,
            "proxies": {},
            "user_agent": "KSJ-DAST-Scanner/1.0"
        }
        for key in ("filedown_data", "ssrf_data"):
            module_data = self._as_dict(pre_data.get(key)).copy()
            normalized[key] = {
                "targets": [
                    self._normalize_attack_target(item)
                    for item in self._as_list(module_data.get("targets"))
                ],
                "options": self._normalize_options(module_data.get("options"), module_options)
            }

        return normalized

    def generate_preprocess_data(self, scan_data: dict):
        """
        Core 연동용 함수.
        scan_data dict를 받아 SQLi/XSS/FileDownload/SSRF 모듈용 입력 JSON 생성.
        """
        prompt = self.build_prompt(scan_data)

        response = self.client.messages.create(
            model=self.model,
            max_tokens=8192,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

        response_text = response.content[0].text
        pre_data = self.parse_llm_json(response_text)
        return self.normalize_preprocess_data(pre_data)

    def load_scan_result(self, filepath: str):
        """
        로컬 테스트용.
        """
        scan_path = self.base_dir / filepath

        with open(scan_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def generate_preprocess_data_from_file(self, filepath: str):
        """
        로컬 scan_result.json 테스트용.
        """
        scan_data = self.load_scan_result(filepath)
        return self.generate_preprocess_data(scan_data)

    def save_preprocess_data(self, pre_data: dict, filename: str = "preprocess_data.json"):
        """
        output 디렉터리에 전처리후 데이터를 저장하도록 함수 구성 테스트간 llm 사용량을 줄이기위함
        """
        output_dir = self.base_dir / "output"
        output_dir.mkdir(parents=True, exist_ok=True)

        output_path = output_dir / filename
        output_path.parent.mkdir(parents=True, exist_ok=True)

        safe_pre_data = self.normalize_preprocess_data(pre_data)
        safe_pre_data = self.make_json_safe(safe_pre_data)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(safe_pre_data, f, ensure_ascii=False, indent=2)

        return output_path


"""
Core 연동 예시:

from ksj_llm.preprocessor_llm import LLMPreprocessor

preprocessor = LLMPreprocessor()
pre_data = preprocessor.generate_preprocess_data(results)

sql_data = pre_data["sql_data"]
xss_data = pre_data["xss_data"]
filedown_data = pre_data["filedown_data"]
ssrf_data = pre_data["ssrf_data"]


# 테스트 반복 시 LLM을 다시 호출하지 않도록 전처리 결과를 로컬에 저장
# 기본 저장 위치: project_root/output/preprocess_data.json
saved_path = preprocessor.save_preprocess_data(pre_data)

# 파일명을 지정하고 싶으면 다음처럼 사용한다.
saved_path = preprocessor.save_preprocess_data(pre_data, "파일명.json")
"""


if __name__ == "__main__":
    # 로컬 테스트
    preprocessor = LLMPreprocessor()
    pre_data = preprocessor.generate_preprocess_data_from_file("full_recon_report.json")
    preprocessor.save_preprocess_data(pre_data)
