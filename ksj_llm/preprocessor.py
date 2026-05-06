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
        for page in crawler.get("public_pages", []):
            response_headers = page.get("response_headers") or {}
            page_urls = [
                page.get("url"),
                *page.get("links", []),
                *page.get("routes", []),
                *page.get("xhr_list", []),
                *page.get("ws_list", []),
                *page.get("endpoint_hints", [])
            ]
            query_source_urls.extend(page_urls)
            pages.append({
                "url": page.get("url"),
                "status": page.get("status"),
                "links": page.get("links", []),
                "routes": page.get("routes", []),
                "forms": page.get("forms", []),
                "technologies": page.get("technologies", []),
                "render_type": page.get("render_type"),
                "xhr_list": page.get("xhr_list", []),
                "ws_list": page.get("ws_list", []),
                "endpoint_hints": page.get("endpoint_hints", []),
                "cookies": page.get("cookies", []),
                "response_headers": {
                    "server": response_headers.get("server"),
                    "set-cookie": response_headers.get("set-cookie"),
                    "content-type": response_headers.get("content-type")
                }
            })

        authenticated_pages = []
        for page in crawler.get("authenticated_pages", []):
            response_headers = page.get("response_headers") or {}
            page_urls = [
                page.get("url"),
                *page.get("links", []),
                *page.get("routes", []),
                *page.get("xhr_list", []),
                *page.get("ws_list", []),
                *page.get("endpoint_hints", [])
            ]
            query_source_urls.extend(page_urls)
            authenticated_pages.append({
                "url": page.get("url"),
                "status": page.get("status"),
                "links": page.get("links", []),
                "routes": page.get("routes", []),
                "forms": page.get("forms", []),
                "xhr_list": page.get("xhr_list", []),
                "ws_list": page.get("ws_list", []),
                "endpoint_hints": page.get("endpoint_hints", []),
                "cookies": page.get("cookies", []),
                "response_headers": {
                    "server": response_headers.get("server"),
                    "set-cookie": response_headers.get("set-cookie"),
                    "content-type": response_headers.get("content-type")
                }
            })

        fuzzer_results = []
        for group in fuzzer.get("results", []):
            for item in group.get("results", []):
                fuzzer_results.append({
                    "url": item.get("url"),
                    "status": item.get("status"),
                    "length": item.get("length"),
                    "risk": item.get("risk")
                })
                query_source_urls.append(item.get("url"))

        ports = []
        for host in nmap.get("hosts", []):
            for port in host.get("ports", []):
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
                    for host in nmap.get("hosts", [])
                ],
                "ports": ports
            },
            "crawler": {
                "target_url": crawler.get("target_url"),
                "public_pages": pages,
                "authenticated_pages": authenticated_pages,
                "query_params": self.extract_query_params(query_source_urls),
                "auth": crawler.get("auth"),
                "sitemap_urls": crawler.get("sitemap_urls", []),
                "robots_info": {
                    "disallowed": robots_info.get("disallowed", []),
                    "sitemaps": robots_info.get("sitemaps", [])
                },
                "endpoint_hints": crawler.get("endpoint_hints", []),
                "errors": crawler.get("errors", [])
            },
            "fuzzer": {
                "base_url": fuzzer.get("base_url"),
                "spider_urls": fuzzer.get("spider_urls", []),
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
        return self.parse_llm_json(response_text)

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


"""
Core 연동 예시:

from ksj_llm.preprocessor_llm import LLMPreprocessor

preprocessor = LLMPreprocessor()
pre_data = preprocessor.generate_preprocess_data(results)

sql_data = pre_data["sql_data"]
xss_data = pre_data["xss_data"]
filedown_data = pre_data["filedown_data"]
ssrf_data = pre_data["ssrf_data"]
"""


if __name__ == "__main__":
    # 로컬 테스트
    preprocessor = LLMPreprocessor()
    pre_data = preprocessor.generate_preprocess_data_from_file("scan_result.json")
    print(pre_data)
