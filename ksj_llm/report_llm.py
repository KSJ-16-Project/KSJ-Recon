import os
import json
from pathlib import Path
from dotenv import load_dotenv
import anthropic
import re
from urllib.parse import urlsplit

try:
    from .dashboard_renderer import DashboardRenderer
except ImportError:
    from dashboard_renderer import DashboardRenderer


class LLMReporter:
    def __init__(self):
        # ksj_llm/report_llm.py 기준으로 프로젝트 루트를 계산한다.
        self.base_dir = Path(__file__).resolve().parent.parent

        # 프로젝트 .env를 우선 로드하고, 실행 위치 기준 .env를 fallback으로 로드한다.
        load_dotenv(self.base_dir / ".env", override=True)
        load_dotenv()

        self.api_key = os.getenv("ANTHROPIC_API_KEY")
        self.model = os.getenv("MODEL_NAME")

        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY가 설정되어 있지 않습니다.")

        if not self.model:
            raise ValueError("MODEL_NAME이 설정되어 있지 않습니다.")

        self.api_key = self.api_key.strip()
        self.model = self.model.strip()

        self.client = anthropic.Anthropic(api_key=self.api_key)
        self.renderer = DashboardRenderer(base_dir=self.base_dir)

    def load_prompt_template(self):
        prompt_path = self.base_dir / "prompts" / "report_prompt.txt"

        with open(prompt_path, "r", encoding="utf-8") as f:
            return f.read()

    def load_scan_result(self, filepath: str):
        scan_path = self.base_dir / filepath

        try:
            with open(scan_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"통합 스캔 파일을 찾을 수 없습니다: {scan_path}")
        except json.JSONDecodeError:
            raise ValueError(f"통합 스캔 파일이 올바른 JSON 형식이 아닙니다: {scan_path}")

    def normalize_mode(self, mode):
        normalized = str(mode or "mode_a").strip().lower()
        if normalized not in ("mode_a", "mode_b"):
            raise ValueError(f"지원하지 않는 report mode입니다: {mode}")
        return normalized

    def make_json_safe(self, obj):
        """
        PageSnapshot 같은 JSON 직렬화 불가능한 객체가 들어와도
        LLM에 넘길 수 있도록 dict/list/string 형태로 변환한다.
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

    def _as_list(self, value):
        return value if isinstance(value, list) else []

    def _short_text(self, value, limit=240):
        if value is None:
            return None
        text = value if isinstance(value, str) else str(value)
        text = re.sub(r"\s+", " ", text).strip()
        if len(text) <= limit:
            return text
        return text[:limit] + "...[truncated]"

    def _limited_strings(self, values, max_items=30, text_limit=240):
        compact = []
        seen = set()
        for value in self._as_list(values):
            text = self._short_text(value, text_limit)
            if not text or text in seen:
                continue
            seen.add(text)
            compact.append(text)
            if len(compact) >= max_items:
                break
        return compact

    def _compact_forms(self, forms, max_items=8):
        compact = []
        for form in self._as_list(forms)[:max_items]:
            if not isinstance(form, dict):
                continue

            fields = []
            for field in self._as_list(form.get("fields") or form.get("inputs"))[:20]:
                if isinstance(field, dict):
                    name = field.get("name") or field.get("id")
                    field_type = field.get("type")
                    if name or field_type:
                        fields.append({
                            key: value
                            for key, value in {
                                "name": self._short_text(name, 80),
                                "type": self._short_text(field_type, 40)
                            }.items()
                            if value not in (None, "", [], {})
                        })
                elif field:
                    fields.append({"name": self._short_text(field, 80)})

            item = {
                "action": self._short_text(form.get("action") or form.get("url"), 240),
                "method": self._short_text(form.get("method"), 12),
                "fields": fields
            }
            compact.append({
                key: value
                for key, value in item.items()
                if value not in (None, "", [], {})
            })
        return compact

    def _cookie_names(self, cookies, max_items=12):
        names = []
        for cookie in self._as_list(cookies)[:max_items]:
            if isinstance(cookie, dict):
                name = cookie.get("name")
            else:
                name = str(cookie).split("=", 1)[0]
            name = self._short_text(name, 80)
            if name:
                names.append(name)
        return names

    def minimize_scan_data(self, scan_data: dict):
        """
        보고서 작성에 필요한 핵심 근거만 남겨 LLM 입력 토큰을 줄인다.
        raw_html/rendered_html/run_dir/saved_path 같은 대용량 필드는 제외한다.
        """
        nmap = scan_data.get("nmap") or {}
        crawler = scan_data.get("crawler") or {}
        fuzzer = scan_data.get("fuzzer") or {}

        hosts = []
        ports = []
        for host in nmap.get("hosts", []):
            hosts.append({
                "ip": host.get("ip"),
                "status": host.get("status")
            })

            for port in host.get("ports", []):
                ports.append({
                    "host": host.get("ip"),
                    "port": port.get("port"),
                    "protocol": port.get("protocol"),
                    "state": port.get("state"),
                    "service": port.get("service"),
                    "product": port.get("product"),
                    "version": port.get("version"),
                    "extra_info": port.get("extra_info"),
                    "cpe": port.get("cpe", [])
                })

        pages = []
        for page in self._as_list(crawler.get("public_pages"))[:40]:
            if not isinstance(page, dict):
                continue
            response_headers = page.get("response_headers") or {}
            pages.append({
                "url": self._short_text(page.get("url"), 300),
                "depth": page.get("depth"),
                "status": page.get("status"),
                "links": self._limited_strings(page.get("links"), 25, 260),
                "routes": self._limited_strings(page.get("routes"), 35, 220),
                "forms": self._compact_forms(page.get("forms"), 8),
                "technologies": self._limited_strings(page.get("technologies"), 20, 80),
                "render_type": page.get("render_type"),
                "xhr_list": self._limited_strings(page.get("xhr_list"), 35, 260),
                "ws_list": self._limited_strings(page.get("ws_list"), 10, 260),
                "endpoint_hints": self._limited_strings(page.get("endpoint_hints"), 35, 260),
                "cookie_names": self._cookie_names(page.get("cookies")),
                "response_headers": {
                    "server": self._short_text(response_headers.get("server"), 120),
                    "content-type": self._short_text(response_headers.get("content-type"), 120),
                    "x-frame-options": self._short_text(response_headers.get("x-frame-options"), 80),
                    "x-content-type-options": self._short_text(response_headers.get("x-content-type-options"), 80)
                }
            })

        authenticated_pages = []
        for page in self._as_list(crawler.get("authenticated_pages"))[:25]:
            if not isinstance(page, dict):
                continue
            response_headers = page.get("response_headers") or {}
            authenticated_pages.append({
                "url": self._short_text(page.get("url"), 300),
                "depth": page.get("depth"),
                "status": page.get("status"),
                "links": self._limited_strings(page.get("links"), 25, 260),
                "routes": self._limited_strings(page.get("routes"), 35, 220),
                "forms": self._compact_forms(page.get("forms"), 8),
                "technologies": self._limited_strings(page.get("technologies"), 20, 80),
                "render_type": page.get("render_type"),
                "xhr_list": self._limited_strings(page.get("xhr_list"), 35, 260),
                "ws_list": self._limited_strings(page.get("ws_list"), 10, 260),
                "endpoint_hints": self._limited_strings(page.get("endpoint_hints"), 35, 260),
                "cookie_names": self._cookie_names(page.get("cookies")),
                "response_headers": {
                    "server": self._short_text(response_headers.get("server"), 120),
                    "content-type": self._short_text(response_headers.get("content-type"), 120),
                    "x-frame-options": self._short_text(response_headers.get("x-frame-options"), 80),
                    "x-content-type-options": self._short_text(response_headers.get("x-content-type-options"), 80)
                }
            })

        fuzzer_results = []
        seen_fuzzer_urls = set()
        for group in self._as_list(fuzzer.get("results")):
            if len(fuzzer_results) >= 250:
                break
            if not isinstance(group, dict):
                continue
            for item in self._as_list(group.get("results")):
                if len(fuzzer_results) >= 250:
                    break
                if not isinstance(item, dict):
                    continue
                url = self._short_text(item.get("url"), 300)
                if not url or url in seen_fuzzer_urls:
                    continue
                seen_fuzzer_urls.add(url)
                fuzzer_results.append({
                    "url": url,
                    "status": item.get("status"),
                    "length": item.get("length"),
                    "risk": item.get("risk")
                })

        robots_info = crawler.get("robots_info") or {}

        return {
            "nmap": {
                "target": nmap.get("target"),
                "scan_time": nmap.get("scan_time"),
                "hosts": hosts,
                "ports": ports
            },
            "crawler": {
                "target_url": crawler.get("target_url"),
                "public_pages": pages,
                "authenticated_pages": authenticated_pages,
                "auth": crawler.get("auth"),
                "sitemap_urls": self._limited_strings(crawler.get("sitemap_urls"), 80, 260),
                "robots_info": {
                    "disallowed": self._limited_strings(robots_info.get("disallowed"), 80, 220),
                    "sitemaps": self._limited_strings(robots_info.get("sitemaps"), 20, 260)
                },
                "endpoint_hints": self._limited_strings(crawler.get("endpoint_hints"), 120, 260),
                "errors": self._limited_strings(crawler.get("errors"), 30, 300)
            },
            "fuzzer": {
                "status": fuzzer.get("status"),
                "base_url": fuzzer.get("base_url"),
                "tld1": fuzzer.get("tld1"),
                "difficulty": fuzzer.get("difficulty"),
                "spider_urls": self._limited_strings(fuzzer.get("spider_urls"), 200, 260),
                "timestamp": fuzzer.get("timestamp"),
                "results": fuzzer_results
            }
        }

    def _truncate_text(self, value, limit=1200):
        if value is None:
            return None

        text = value if isinstance(value, str) else json.dumps(
            self.make_json_safe(value),
            ensure_ascii=False
        )

        if len(text) <= limit:
            return text

        return text[:limit] + "...[truncated]"

    def _normalize_risk(self, value):
        if value is None:
            return None

        risk = str(value).strip().upper()
        mapping = {
            "CRITICAL": "HIGH",
            "HIGH": "HIGH",
            "H": "HIGH",
            "MEDIUM": "MEDIUM",
            "MID": "MEDIUM",
            "M": "MEDIUM",
            "LOW": "LOW",
            "L": "LOW",
            "INFO": "LOW",
            "INFORMATIONAL": "LOW"
        }
        return mapping.get(risk, risk)

    def _normalize_status(self, item):
        if not isinstance(item, dict):
            return None

        for key in ("status", "result", "state"):
            if item.get(key) is not None:
                return str(item.get(key))

        for key in ("vulnerable", "confirmed", "success", "detected"):
            if item.get(key) is not None:
                value = item.get(key)
                if isinstance(value, str):
                    return "confirmed" if value.strip().lower() in ("1", "true", "yes", "y") else "not_confirmed"
                return "confirmed" if bool(value) else "not_confirmed"

        return None

    def _pick_first(self, source, keys):
        if not isinstance(source, dict):
            return None

        for key in keys:
            value = source.get(key)
            if value not in (None, "", [], {}):
                return value
        return None

    def _pick_payload_example(self, item):
        if not isinstance(item, dict):
            return None

        direct = self._pick_first(item, (
            "payload_example", "test_payload", "proof_payload", "payload"
        ))
        if direct not in (None, "", [], {}):
            return direct

        payloads = item.get("payloads")
        if isinstance(payloads, list):
            examples = []
            for payload in payloads:
                if payload in (None, "", [], {}):
                    continue
                if isinstance(payload, dict):
                    value = self._pick_first(payload, (
                        "payload", "value", "example", "test_payload", "proof_payload"
                    ))
                    if value in (None, "", [], {}):
                        value = payload
                else:
                    value = payload

                text = self._truncate_text(value, limit=240)
                if text:
                    examples.append(text)
                if len(examples) >= 3:
                    break

            if examples:
                return " | ".join(examples)

        return None

    def _extract_attack_items(self, module_data):
        if module_data is None:
            return []

        if isinstance(module_data, list):
            return module_data

        if not isinstance(module_data, dict):
            return [module_data]

        for key in ("results", "findings", "vulnerabilities", "issues", "items", "data"):
            value = module_data.get(key)
            if isinstance(value, list):
                return value

        return [module_data]

    def _url_path_param_key(self, url, param):
        try:
            parsed = urlsplit(str(url or ""))
            path_key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.scheme and parsed.netloc else str(url or "")
        except ValueError:
            path_key = str(url or "")

        return (path_key.rstrip("/"), str(param or "").strip())

    def _pick_sqli_payload_example(self, module_data):
        if not isinstance(module_data, dict):
            return None

        technique_queries = module_data.get("technique_queries")
        if not isinstance(technique_queries, dict):
            return self._pick_payload_example(module_data)

        unsafe_technique_words = (
            "file", "outfiles", "outfile", "xp_cmdshell", "stacked", "info"
        )

        examples = []
        for section_name in ("confirmed", "possible"):
            section = technique_queries.get(section_name)
            if not isinstance(section, dict):
                continue

            for technique, payloads in section.items():
                technique_text = str(technique or "").strip().lower()
                if any(word in technique_text for word in unsafe_technique_words):
                    continue

                for payload in self._as_list(payloads):
                    text = self._truncate_text(payload, limit=240)
                    if text:
                        examples.append(text)
                    if len(examples) >= 2:
                        return " | ".join(examples)

        return examples[0] if examples else None

    def _extract_sqli_items(self, module_data):
        if not isinstance(module_data, dict):
            return []

        injectable_params = module_data.get("injectable_params")
        if not isinstance(injectable_params, list):
            return []

        dbms_type = module_data.get("dbms_type")
        confidence = module_data.get("confidence")
        status = "confirmed" if str(confidence or "").strip().lower() == "high" else "detected"
        module_target = self._pick_first(module_data, ("target", "target_url", "url", "endpoint", "request_url", "path"))
        payload_example = self._pick_sqli_payload_example(module_data)

        def normalize_values(value):
            values = value if isinstance(value, list) else []
            normalized = []
            for item_value in values:
                if item_value in (None, "", [], {}):
                    continue
                text = self._short_text(item_value, 80)
                if text and text not in normalized:
                    normalized.append(text)
                if len(normalized) >= 5:
                    break
            return normalized

        def target_with_values(url, param, values):
            if not url or not param or not values:
                return url
            try:
                parsed = urlsplit(str(url))
                if parsed.query:
                    return url
            except ValueError:
                pass
            return f"{url}?{param}={values[0]}"

        deduped = {}
        for item in injectable_params:
            if isinstance(item, dict):
                url = self._pick_first(item, ("target", "target_url", "url", "endpoint", "request_url", "path"))
                param = self._pick_first(item, ("param", "parameter", "field", "input_name", "name"))
                values = normalize_values(
                    item.get("values") or item.get("observed_values") or item.get("sample_values")
                )
            else:
                url = module_target
                param = str(item).strip()
                values = []
            if not url and not param:
                continue

            key = self._url_path_param_key(url, param)
            if key not in deduped:
                deduped[key] = {
                    "target": target_with_values(url, param, values),
                    "parameter": param,
                    "vulnerability": "SQL injection candidate",
                    "risk": "HIGH" if status == "confirmed" else "MEDIUM",
                    "status": status,
                    "evidence": (
                        f"SQLi module reported injectable parameter '{param}' "
                        f"with confidence={confidence or '-'}"
                        + (f"; observed values: {', '.join(values)}" if values else "")
                    ),
                    "payload_example": payload_example,
                    "observed_values": ", ".join(values) if values else None,
                    "dbms_type": dbms_type,
                    "confidence": confidence,
                    "duplicate_count": 1
                }
            else:
                deduped[key]["duplicate_count"] += 1
                existing_values = deduped[key].get("observed_values")
                existing = [value.strip() for value in str(existing_values or "").split(",") if value.strip()]
                changed = False
                for value in values:
                    if value not in existing:
                        existing.append(value)
                        changed = True
                    if len(existing) >= 5:
                        break
                if changed:
                    deduped[key]["observed_values"] = ", ".join(existing)
                    deduped[key]["evidence"] = (
                        f"SQLi module reported injectable parameter '{param}' "
                        f"with confidence={confidence or '-'}"
                        f"; observed values: {', '.join(existing)}"
                    )

        return list(deduped.values())

    def minimize_attack_results(self, attacks: dict):
        """
        공격 모듈 결과를 보고서 근거로 쓰기 좋게 축약한다.
        대용량 원문 필드는 의도적으로 제외한다.
        """
        if not isinstance(attacks, dict):
            return []

        attack_results = []
        excluded_keys = {
            "raw_html", "rendered_html", "html", "body", "content",
            "raw_response", "response_body", "request_body",
            "exploit", "exploit_code",
            "screenshot", "screenshot_path", "saved_path", "run_dir",
            "debug", "logs", "traceback"
        }

        known_keys = {
            "target", "target_url", "url", "endpoint", "request_url", "path",
            "method", "http_method", "parameter", "param", "field", "input_name",
            "vulnerability", "type", "name", "title", "check",
            "risk", "severity", "level", "status", "result", "state",
            "vulnerable", "confirmed", "success", "detected",
            "payload", "payload_example", "test_payload", "proof_payload",
            "evidence", "proof", "detail", "details", "message",
            "reason", "description", "response_status", "status_code",
            "http_status", "recommendation", "remediation", "fix"
        }

        max_attack_items = 300
        for module_name, module_data in attacks.items():
            if len(attack_results) >= max_attack_items:
                break
            module_items = []
            if str(module_name).strip().lower() == "sqli":
                module_items = self._extract_sqli_items(module_data)
            if not module_items:
                module_items = self._extract_attack_items(module_data)

            for item in module_items:
                if len(attack_results) >= max_attack_items:
                    break
                if isinstance(item, dict):
                    compact = {
                        "module": str(module_name),
                        "target": self._pick_first(item, ("target", "target_url", "url", "endpoint", "request_url", "path")),
                        "method": self._pick_first(item, ("method", "http_method")),
                        "parameter": self._pick_first(item, ("parameter", "param", "field", "input_name")),
                        "vulnerability": self._pick_first(item, ("vulnerability", "type", "name", "title", "check")),
                        "risk": self._normalize_risk(self._pick_first(item, ("risk", "severity", "level"))),
                        "status": self._normalize_status(item),
                        "payload_example": self._truncate_text(
                            self._pick_payload_example(item),
                            limit=800
                        ),
                        "evidence": self._truncate_text(self._pick_first(item, (
                            "evidence", "proof", "detail", "details", "message", "reason", "description"
                        ))),
                        "response_status": self._pick_first(item, ("response_status", "status_code", "http_status")),
                        "recommendation_hint": self._pick_first(item, ("recommendation", "remediation", "fix"))
                    }

                    extras = {}
                    for key, value in item.items():
                        if key in excluded_keys or key in known_keys:
                            continue
                        if isinstance(value, (str, int, float, bool)) or value is None:
                            extras[key] = value

                    if extras:
                        compact["extra"] = extras

                    attack_results.append({
                        key: value
                        for key, value in compact.items()
                        if value not in (None, "", [], {})
                    })
                else:
                    attack_results.append({
                        "module": str(module_name),
                        "evidence": self._truncate_text(item)
                    })

        return attack_results

    def minimize_report_input(self, input_data: dict, mode="mode_a"):
        mode = self.normalize_mode(mode)

        if mode == "mode_a":
            return self.minimize_scan_data(input_data)

        scan_data = input_data.get("scan") or input_data.get("scan_data") or {}
        attacks = input_data.get("attacks") or input_data.get("attack_results") or {}
        metadata = input_data.get("metadata") or {}

        if not scan_data:
            scan_data = {
                "nmap": input_data.get("nmap") or {},
                "crawler": input_data.get("crawler") or {},
                "fuzzer": input_data.get("fuzzer") or {}
            }

        return {
            "mode": "mode_b",
            "report_instructions": [
                "Use scan_summary and attack_results together as evidence.",
                "Prioritize attack module results marked confirmed, vulnerable, success, detected, or equivalent in findings.",
                "Do not describe inconclusive, failed, not_confirmed, or missing results as confirmed vulnerabilities.",
                "For attack-module findings, use one category from SQLi, XSS, FileDownload, SSRF, Web, Network, or Other.",
                "For SQLi, XSS, FileDownload, and SSRF findings, include findings[].payload_example when attack_results contains payload_example, test_payload, proof_payload, payload, or payloads.",
                "When attack_results contains multiple SQLi items with different target path and parameter pairs, preserve them as distinct findings instead of collapsing them into one generic SQLi finding.",
                "For SQLi findings, include observed parameter values from target, evidence, or extra.observed_values when present.",
                "Use payload_example only as a short diagnostic verification string copied or summarized from attack_results. Do not invent payloads."
            ],
            "metadata": {
                "target": metadata.get("target") or input_data.get("target"),
                "scan_time": metadata.get("scan_time") or input_data.get("scan_time")
            },
            "scan_summary": self.minimize_scan_data(scan_data),
            "attack_results": self.minimize_attack_results(attacks)
        }

    def build_prompt(self, scan_data: dict, mode="mode_a"):
        mode = self.normalize_mode(mode)
        prompt_template = self.load_prompt_template()
        if mode == "mode_b":
            prompt_template += """

[MODE B Additional Analysis Rules]
- Analyze scan_summary and attack_results together.
- attack_results contains execution results from SQLi, XSS, FileDownload, SSRF, or other attack modules.
- Results marked as confirmed, vulnerable, success, detected, or equivalent must take priority over reconnaissance-only hints in findings.
- Items marked as inconclusive, failed, not_confirmed, or with no result must not be described as confirmed vulnerabilities.
- In mode_b, findings[].category may be one of "Network", "Web", "SQLi", "XSS", "FileDownload", "SSRF", or "Other".
- This category rule overrides the mode_a category restriction from report_prompt.txt.
- Write all human-readable report fields in Korean.
- If attack_results contains multiple SQLi items with different target path and parameter pairs, keep those distinct SQLi candidates as separate findings. Do not collapse all SQLi evidence into one finding unless the target path and parameter are the same.
- For SQLi findings, include observed parameter values from attack_results.target, attack_results.evidence, or attack_results.extra.observed_values when present.
- For findings derived from SQLi, XSS, FileDownload, or SSRF attack_results, include findings[].payload_example when a provided payload_example, test_payload, proof_payload, payload, or payloads value exists.
- payload_example must be copied or briefly summarized from attack_results and must remain a short diagnostic verification string, not a full exploit procedure.
- If no provided payload exists for a finding, set payload_example to "-".
- Do not include automated attack code, bypass procedures, destructive steps, or data exfiltration procedures in the final report.
"""

        safe_scan_data = self.make_json_safe(scan_data)
        minimal_scan_data = self.minimize_report_input(safe_scan_data, mode=mode)
        combined_data = json.dumps(
            minimal_scan_data,
            ensure_ascii=False,
            separators=(",", ":")
        )

        json_output_rule = """
[Final Output Rules / STRICT JSON OUTPUT]
Return only one valid JSON object.
Do not output markdown, explanations, code fences, or comments.
Follow the output JSON schema from report_prompt.txt exactly.
Do not add trailing commas.
Keep JSON keys and enum values in English.
Write human-readable report fields such as "summary", "title", "evidence", "impact", "recommendation", "entry_point", "steps", and "limitations" in Korean.
"""

        return f"{prompt_template}\n\n{json_output_rule}\n\n[Scan Data]\n{combined_data}"

    def parse_llm_json(self, response_text: str):
        """
        Claude 응답에서 JSON 객체만 안전하게 파싱한다.
        원칙적으로 JSON만 반환해야 하지만, 코드블록이나 앞뒤 설명이 섞인
        경우를 대비해 JSON 객체 영역을 한 번 더 추출한다.
        """
        return self._parse_llm_json_text(response_text)

    def _strip_json_text(self, response_text: str):
        text = response_text.strip()

        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text)
            text = re.sub(r"\s*```$", "", text)
            text = text.strip()

        return re.sub(r",\s*([}\]])", r"\1", text)

    def _extract_json_object_text(self, text: str):
        start = text.find("{")
        if start == -1:
            return None

        in_string = False
        escaped = False
        depth = 0

        for index in range(start, len(text)):
            char = text[index]

            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == "\"":
                    in_string = False
                continue

            if char == "\"":
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return text[start:index + 1]

        end = text.rfind("}")
        if end != -1 and start < end:
            return text[start:end + 1]

        return None

    def _parse_llm_json_text(self, response_text: str):
        text = self._strip_json_text(response_text)

        try:
            return json.loads(text)
        except json.JSONDecodeError as original_error:
            candidate = self._extract_json_object_text(text)

            if candidate:
                candidate = re.sub(r",\s*([}\]])", r"\1", candidate)
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError as candidate_error:
                    original_error = candidate_error

            raise ValueError(
                "LLM 응답이 올바른 JSON 형식이 아닙니다. "
                "프롬프트의 JSON 출력 강제 조건을 확인하세요. "
                f"JSON error: {original_error.msg} "
                f"(line {original_error.lineno}, column {original_error.colno}, char {original_error.pos})"
            ) from original_error

    def repair_llm_json(self, response_text: str, parse_error: Exception):
        repair_prompt = f"""
Return only one valid JSON object.
Fix the malformed dashboard JSON below so it can be parsed by json.loads.
Preserve the original meaning and available fields as much as possible.
If the text is truncated, close the current string/object/array and use "-" or [] for missing values.
Do not include markdown, comments, explanations, or code fences.

[Parse Error]
{parse_error}

[Malformed JSON]
{response_text}
"""

        repaired_text = self.create_message_text(repair_prompt, max_tokens=24000)
        return self._parse_llm_json_text(repaired_text)

    def create_message_text(self, prompt: str, max_tokens=24000):
        chunks = []

        with self.client.messages.stream(
            model=self.model.strip(),
            max_tokens=max_tokens,
            messages=[
                {"role": "user", "content": prompt}
            ]
        ) as stream:
            for text in stream.text_stream:
                chunks.append(text)

        return "".join(chunks)

    def generate_report_from_data(self, scan_data: dict, mode="mode_a"):
        mode = self.normalize_mode(mode)
        prompt = self.build_prompt(scan_data, mode=mode)

        response_text = self.create_message_text(prompt, max_tokens=24000)

        try:
            return self.parse_llm_json(response_text)
        except ValueError as error:
            return self.repair_llm_json(response_text, error)

    def render_dashboard(self, report_data: dict, output_filename="dashboard.html"):
        return self.renderer.render_from_report_data(
            report_data=report_data,
            output_filename=output_filename
        )

    def generate_dashboard_from_data(self, scan_data: dict, output_filename="dashboard.html", mode="mode_a"):
        """
        Core 연동 함수.
        input_data dict와 mode를 받아 LLM 분석, JSON 파싱, HTML 렌더링까지 수행한다.
        """
        if output_filename in ("mode_a", "mode_b") and mode == "mode_a":
            mode = output_filename
            output_filename = "dashboard.html"

        mode = self.normalize_mode(mode)
        report_data = self.generate_report_from_data(scan_data, mode=mode)
        dashboard_path = self.render_dashboard(report_data, output_filename)

        return {
            "mode": mode,
            "report_data": report_data,
            "dashboard_path": dashboard_path
        }

    def generate_dashboard_from_scan_file(self, filepath: str, output_filename="dashboard.html", mode="mode_a"):
        """
        로컬 테스트용 함수.
        scan_result.json 또는 mode_b 입력 JSON 파일을 읽어 LLM 분석과 HTML 렌더링까지 수행한다.
        """
        if output_filename in ("mode_a", "mode_b") and mode == "mode_a":
            mode = output_filename
            output_filename = "dashboard.html"

        mode = self.normalize_mode(mode)
        scan_data = self.load_scan_result(filepath)
        return self.generate_dashboard_from_data(scan_data, output_filename, mode=mode)


def generate_report_dashboard(input_data: dict, mode="mode_a", output_filename="dashboard.html"):
    """
    Core에서 호출하는 단일 진입점.
    Core는 input_data와 mode만 넘기고, Reporter 생성/LLM 분석/HTML 렌더링은 이 함수 내부에서 처리한다.
    """
    reporter = LLMReporter()
    return reporter.generate_dashboard_from_data(
        scan_data=input_data,
        output_filename=output_filename,
        mode=mode
    )


def generate_report_dashboard_from_file(filepath: str, mode="mode_a", output_filename="dashboard.html"):
    """
    로컬 파일 기반 테스트 진입점.
    """
    reporter = LLMReporter()
    return reporter.generate_dashboard_from_scan_file(
        filepath=filepath,
        output_filename=output_filename,
        mode=mode
    )


"""
Core 연동 예시:

from ksj_llm.report_llm import generate_report_dashboard

result = generate_report_dashboard(
    input_data=input_data,
    mode=mode,
    output_filename="dashboard.html"
)

report_data = result["report_data"]
dashboard_path = result["dashboard_path"]


# mode_a: 기존 통합 스캔 데이터만 사용하는 보고서
mode_a_result = generate_report_dashboard(
    input_data=scan_results,
    mode="mode_a",
    output_filename="dashboard_mode_a.html"
)

# mode_b: 통합 스캔 데이터 + 공격 모듈 결과를 함께 사용하는 보고서
mode_b_result = generate_report_dashboard(
    input_data=mode_b_input,
    mode="mode_b",
    output_filename="dashboard_mode_b.html"
)

# mode_b input data 형태 참고용입니다.
mode_b_input = {
    "scan": {
        "nmap": nmap_result,
        "crawler": crawler_result,
        "fuzzer": fuzzer_result
    },
    "attacks": {
        "sqli": sqli_result,
        "xss": xss_result,
        "file_download": filedown_result,
        "ssrf": ssrf_result
    },
    "metadata": {
        "target": target,
        "scan_time": scan_time
    }
}

# 로컬 파일 테스트는 generate_report_dashboard_from_file()을 사용한다.
"""


if __name__ == "__main__":
    result = generate_report_dashboard_from_file(
        filepath="full_recon_report.json",
        mode="mode_a",
        output_filename="hotspot_0506_01.html"
    )

    print(f"[+] 대시보드 저장 완료: {result['dashboard_path']}")
    print(json.dumps(result["report_data"], indent=2, ensure_ascii=False))
