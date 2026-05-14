"""Build report-friendly JSON results."""

from __future__ import annotations

from datetime import datetime
from urllib.parse import urlparse


class ResultBuilder:
    def build(
        self,
        *,
        base_url: str,
        results: list[dict],
        errors: list[dict],
        total_targets: int,
        options: dict,
        skipped: list[dict] | None = None,
    ) -> dict:
        skipped = skipped or []
        summary = {
            "total_targets": total_targets,
            "total_findings": len(results),
            "verified_findings": sum(1 for r in results if r.get("browser_verified")),
            "high": sum(1 for r in results if r.get("risk") == "HIGH"),
            "medium": sum(1 for r in results if r.get("risk") == "MEDIUM"),
            "low": sum(1 for r in results if r.get("risk") == "LOW"),
            "info": sum(1 for r in results if r.get("risk") == "INFO"),
            "errors": len(errors),
            "skipped": len(skipped),
        }
        return {
            "status": "ok" if not errors else "partial_ok",
            "result_type": "partial" if options.get("partial") else "final",
            "complete": not bool(options.get("partial")) and not errors,
            "module": "xss_module",
            "version": "2.1-lightweight",
            "base_url": base_url,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "summary": summary,
            "scope": {
                "supported": [
                    "Reflected XSS candidate detection for GET parameters",
                    "Conditional browser verification for high-risk reflected candidates",
                    "Limited stored XSS candidate detection for explicitly safe POST forms",
                    "Optional hash/fragment-based DOM XSS verification with Playwright",
                    "POST reflected XSS detection for form and JSON body parameters",
                ],
                "excluded_or_limited": [
                    "Full DOM XSS data-flow analysis is not implemented",
                    "Basic WAF detection and bypass payload retry are supported, but advanced WAF bypass is not implemented",
                    "Stored XSS verification is limited to observable post-submit reflections",
                    "Authenticated workflows require cookies/headers in input JSON",
                    "DOM Stored XSS (dom_stored_xss) is disabled by default due to auto-form-submission side effects; enable explicitly with options.dom_stored_xss=true",
                    "Stored XSS and DOM stored XSS scans submit live form data to target endpoints; only safe_to_submit=true targets are tested, but database side effects (test data persistence) cannot be ruled out",
                    # Stored/DOM Stored XSS는 실제 POST 제출을 수행하므로, 보고서 JSON에서도
                    # side effect 가능성을 명시해 사용자가 결과 해석 시 오해하지 않게 한다.
                    "Stored XSS 및 DOM Stored XSS 검증은 실제 폼 제출을 수행하므로 "
                    "테스트 데이터가 대상 서버에 저장될 수 있습니다. "
                    "safe_to_submit=True로 설정된 타겟에만 실행됩니다.",
                ],
                "options": options,
            },
            "results": results,
            "llm_evidence": self.to_llm_payload({"base_url": base_url, "timestamp": datetime.now().isoformat(timespec="seconds"), "summary": summary, "results": results}),
            "skipped": skipped,
            "errors": errors,
        }

    def to_llm_payload(self, full_result: dict) -> dict:
        """Return a minimal subset of full_result for LLM report generation.

        Only browser-verified script execution evidence is included. HTTP-only
        candidates are intentionally omitted to reduce false positives in LLM
        reporting.
        """
        slim_findings = []
        for f in full_result.get("results", []):
            verified = bool(f.get("browser_verified"))
            if not verified:
                continue
            entry: dict = {
                "url": f.get("url", ""),
                "param": f.get("param"),
                "method": f.get("method", "GET"),
                "context": f.get("context"),
                "verified": verified,
            }
            entry["payload"] = f.get("payload")
            evidence = f.get("evidence") or {}
            entry["target_url"] = evidence.get("target_url") or evidence.get("checked_url") or f.get("url")
            entry["alert_text"] = evidence.get("alert_text")
            entry["verification_method"] = evidence.get("verification_method")
            slim_findings.append(entry)

        slim_findings = self._group_verified_findings(slim_findings)

        summary = full_result.get("summary", {})
        return {
            "base_url": full_result.get("base_url", ""),
            "timestamp": full_result.get("timestamp", ""),
            "summary": {
                "total_findings": summary.get("total_findings", 0),
                "verified": summary.get("verified_findings", summary.get("high", 0)),
                "candidates": summary.get("medium", 0) + summary.get("low", 0),
            },
            "findings": slim_findings,
        }

    def _group_verified_findings(self, findings: list[dict]) -> list[dict]:
        """Group near-duplicate reflected findings for cleaner LLM reporting."""
        grouped: dict[tuple, dict] = {}
        ordered: list[dict] = []
        for f in findings:
            parsed = urlparse(f.get("url", ""))
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.scheme and parsed.netloc else f.get("url", "")
            key = (
                f.get("method", "GET"),
                base_url,
                f.get("param"),
                f.get("context"),
            )
            if key not in grouped:
                g = dict(f)
                g["url"] = base_url or f.get("url", "")
                g["target_examples"] = [f.get("target_url")]
                g["variant_count"] = 1
                grouped[key] = g
                ordered.append(g)
                continue

            g = grouped[key]
            g["variant_count"] = int(g.get("variant_count", 1)) + 1
            t = f.get("target_url")
            examples = g.setdefault("target_examples", [])
            if t and t not in examples and len(examples) < 5:
                examples.append(t)
        return ordered

    def finding(self, **kwargs) -> dict:
        return kwargs

    def error(self, *, url: str, phase: str, error: str, detail: str = "",
              category: str = "network_error", verification_status: str | None = None) -> dict:
        # category: auth_failed | network_error | timeout | waf_block | browser_error | parse_error
        data = {"url": url, "phase": phase, "error": error, "detail": detail, "category": category}
        if verification_status:
            data["verification_status"] = verification_status
        return data
