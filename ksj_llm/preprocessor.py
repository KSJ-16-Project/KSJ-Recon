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

    def _as_port(self, value):
        if isinstance(value, bool) or value is None:
            return ""
        try:
            return int(value)
        except (TypeError, ValueError):
            return self._as_str(value)

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
        param = self._as_dict(item)
        location = self._as_str(param.get("location") or "unknown").lower()
        if location == "param":
            location = "query"
        if location not in ("query", "body", "header", "unknown"):
            location = "unknown"

        return {
            "name": self._as_str(param.get("name")),
            "location": location,
            "value": self._as_str(param.get("value"))
        }

    def _is_valid_sql_param(self, item):
        param = self._as_dict(item)
        location = self._as_str(param.get("location") or "unknown").lower()
        if location == "param":
            location = "query"
        if location == "path":
            return False
        if location not in ("query", "body", "header", "unknown"):
            return False
        return bool(self._as_str(param.get("name")).strip())

    def _normalize_sql_endpoint(self, item):
        endpoint = self._as_dict(item)
        method = self._as_str(endpoint.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            method = "GET"

        return {
            "url": self._as_str(endpoint.get("url")),
            "method": method,
            "enctype": self._as_str(endpoint.get("enctype")),
            "params": [
                self._normalize_sql_param(param)
                for param in self._as_list(endpoint.get("params"))
                if self._is_valid_sql_param(param)
            ]
        }

    def _is_valid_sql_endpoint(self, item):
        endpoint = self._as_dict(item)
        return bool(
            self._as_str(endpoint.get("url")).strip()
            and any(
                self._is_valid_sql_param(param)
                for param in self._as_list(endpoint.get("params"))
            )
        )

    def _normalize_xss_url(self, item):
        if isinstance(item, str):
            return {"url": item}

        target = self._as_dict(item)
        submit_url = self._as_str(target.get("submit_url") or target.get("url"))
        view_url = self._as_str(target.get("view_url"))
        source_url = self._as_str(target.get("source_url") or target.get("source"))
        method = self._as_str(target.get("method") or "GET").upper()
        target_type = self._as_str(target.get("type")).lower()
        body_format = self._as_str(target.get("body_format")).lower()
        body = self._as_dict(target.get("body") or target.get("params") or target.get("data"))
        fields = self._as_dict(target.get("fields"))
        attack_params = self._as_string_list(target.get("attack_params") or target.get("inject_params"))

        if target_type == "dom_hash":
            normalized = {
                "url": submit_url,
                "type": "dom_hash"
            }
        elif target_type == "form":
            normalized = {
                "url": submit_url,
                "type": "form",
                "fields": fields,
                "attack_params": attack_params,
                "safe_to_submit": self._as_bool(target.get("safe_to_submit"), True)
            }
        else:
            normalized = {
                "url": submit_url,
                "method": method if method in ("GET", "POST") else "GET",
                "params": body,
                "attack_params": attack_params
            }

        if view_url:
            normalized["view_url"] = view_url
        if source_url:
            normalized["source_url"] = source_url
        if body_format in ("form", "json"):
            normalized["body_format"] = body_format
        headers = self._as_dict(target.get("headers"))
        if headers:
            normalized["headers"] = headers
        cookies = self._as_dict(target.get("cookies"))
        if cookies:
            normalized["cookies"] = cookies
        return normalized

    def _is_valid_xss_url(self, item):
        if isinstance(item, str):
            return bool(parse_qs(urlparse(item).query, keep_blank_values=True))

        target = self._as_dict(item)
        submit_url = self._as_str(target.get("submit_url") or target.get("url"))
        if not submit_url.strip():
            return False
        method = self._as_str(target.get("method") or "GET").upper()
        target_type = self._as_str(target.get("type")).lower()
        body = self._as_dict(target.get("body") or target.get("params") or target.get("data"))
        fields = self._as_dict(target.get("fields"))

        if target_type == "dom_hash":
            return True
        if target_type == "form":
            return bool(fields or self._as_bool(target.get("safe_to_submit"), True))
        if method == "POST":
            return bool(body)
        if method == "GET":
            return bool(body or parse_qs(urlparse(submit_url).query, keep_blank_values=True))
        return False

    def _normalize_xss_stored_target(self, item):
        target = self._as_dict(item)
        check_urls = self._as_string_list(target.get("check_urls"))
        view_url = self._as_str(target.get("view_url") or (check_urls[0] if check_urls else ""))
        body_format = self._as_str(target.get("body_format")).lower()
        params = self._as_dict(target.get("body") or target.get("params"))
        normalized_check_urls = []
        for url in [view_url, *check_urls]:
            if url and url not in normalized_check_urls:
                normalized_check_urls.append(url)

        normalized = {
            "url": self._as_str(target.get("submit_url") or target.get("url")),
            "params": params,
            "check_urls": normalized_check_urls,
            "attack_params": self._as_string_list(target.get("attack_params") or target.get("inject_params")),
            "safe_to_submit": self._as_bool(target.get("safe_to_submit"), True)
        }
        method = self._as_str(target.get("method")).upper()
        if method in ("GET", "POST"):
            normalized["method"] = method
        if body_format in ("form", "json"):
            normalized["body_format"] = body_format
        headers = self._as_dict(target.get("headers"))
        if headers:
            normalized["headers"] = headers
        cookies = self._as_dict(target.get("cookies"))
        if cookies:
            normalized["cookies"] = cookies
        return normalized

    def _is_valid_xss_stored_target(self, item):
        target = self._as_dict(item)
        submit_url = self._as_str(target.get("submit_url") or target.get("url"))
        check_urls = self._as_string_list(target.get("check_urls"))
        view_url = self._as_str(target.get("view_url") or (check_urls[0] if check_urls else ""))
        body = self._as_dict(target.get("body") or target.get("params"))
        return bool(
            submit_url.strip()
            and view_url.strip()
            and body
        )

    def _normalize_xss_options(self, value):
        return self._as_dict(value).copy()

    def _normalize_attack_target(self, item):
        target = self._as_dict(item)
        normalized = {}
        url = self._as_str(target.get("url"))
        if url:
            normalized["url"] = url

        params = self._as_dict(target.get("params"))
        if params:
            normalized["params"] = params

        inject_params = self._as_string_list(target.get("inject_params"))
        if inject_params:
            normalized["inject_params"] = inject_params

        method = self._as_str(target.get("method")).upper()
        if method in ("GET", "POST"):
            normalized["method"] = method

        data = self._as_dict(target.get("data"))
        if data:
            normalized["data"] = data

        headers = self._as_dict(target.get("headers"))
        if headers:
            normalized["headers"] = headers

        if target.get("timeout") is not None:
            normalized["timeout"] = self._as_float(target.get("timeout"), 5.0)

        return normalized

    def _normalize_module_options(self, value):
        options = self._as_dict(value)
        normalized = {}
        option_defaults = {
            "max_workers": 4,
            "timeout": 10.0,
            "verify": False,
            "allow_redirects": False,
            "proxies": {},
            "user_agent": "KSJ-DAST-Scanner/1.0"
        }
        for key, default_value in option_defaults.items():
            if key not in options:
                continue
            current_value = options.get(key)
            if isinstance(default_value, bool):
                normalized[key] = self._as_bool(current_value, default_value)
            elif isinstance(default_value, int) and not isinstance(default_value, bool):
                normalized[key] = self._as_int(current_value, default_value)
            elif isinstance(default_value, float):
                normalized[key] = self._as_float(current_value, default_value)
            elif isinstance(default_value, dict):
                normalized[key] = self._as_dict(current_value)
            else:
                normalized[key] = self._as_str(current_value)
        return normalized

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
                "auth": {
                    "cookie": self._as_str(auth.get("cookie")),
                    "Authorization": self._as_str(auth.get("Authorization")),
                    "Referer": self._as_str(auth.get("Referer")),
                    "Accept-Language": self._as_str(auth.get("Accept-Language"))
                },
                "nmap_data": {
                    "port": self._as_port(nmap_data.get("port")),
                    "service": self._as_str(nmap_data.get("service")),
                    "version": self._as_str(nmap_data.get("version"))
                },
                "endpoints": [
                    self._normalize_sql_endpoint(item)
                    for item in self._as_list(sql_data.get("endpoints"))
                    if self._is_valid_sql_endpoint(item)
                ]
            },
            "xss_data": {},
            "filedown_data": {},
            "ssrf_data": {}
        }

        xss_data = self._as_dict(pre_data.get("xss_data")).copy()
        normalized["xss_data"] = {
            "base_url": self._as_str(xss_data.get("base_url")),
            "headers": self._as_dict(xss_data.get("headers")),
            "cookies": self._as_dict(xss_data.get("cookies")),
            "spider_urls": self._as_string_list(xss_data.get("spider_urls")),
            "urls": [
                self._normalize_xss_url(item)
                for item in self._as_list(xss_data.get("urls"))
                if self._is_valid_xss_url(item)
            ],
            "stored_targets": [
                self._normalize_xss_stored_target(item)
                for item in self._as_list(xss_data.get("stored_targets"))
                if self._is_valid_xss_stored_target(item)
            ],
            "options": self._normalize_xss_options(xss_data.get("options"))
        }

        for key in ("filedown_data", "ssrf_data"):
            module_data = self._as_dict(pre_data.get(key)).copy()
            target = module_data.get("target")
            if target is None:
                targets = self._as_list(module_data.get("targets"))
                target = targets[0] if targets else {}
            normalized[key] = {
                "target": self._normalize_attack_target(target)
            }
            options = self._normalize_module_options(module_data.get("options"))
            if options:
                normalized[key]["options"] = options

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

    def save_preprocess_data(self, pre_data: dict, filename: str = "preprocess_data_new1.json"):
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
