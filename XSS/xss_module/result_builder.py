"""Build report-friendly JSON results."""

from __future__ import annotations

from datetime import datetime


class ResultBuilder:
    def build(self, *, base_url: str, results: list[dict], errors: list[dict], total_targets: int, options: dict) -> dict:
        summary = {
            "total_targets": total_targets,
            "total_findings": len(results),
            "high": sum(1 for r in results if r.get("risk") == "HIGH"),
            "medium": sum(1 for r in results if r.get("risk") == "MEDIUM"),
            "low": sum(1 for r in results if r.get("risk") == "LOW"),
            "info": sum(1 for r in results if r.get("risk") == "INFO"),
            "errors": len(errors),
        }
        return {
            "status": "ok" if not errors else "partial_ok",
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
                    "WAF bypass and large payload fuzzing are not implemented",
                    "Stored XSS verification is limited to observable post-submit reflections",
                    "Authenticated workflows require cookies/headers in input JSON",
                    "DOM Stored XSS (dom_stored_xss) is disabled by default due to auto-form-submission side effects; enable explicitly with options.dom_stored_xss=true",
                ],
                "options": options,
            },
            "results": results,
            "errors": errors,
        }

    def finding(self, **kwargs) -> dict:
        return kwargs

    def error(self, *, url: str, phase: str, error: str, detail: str = "") -> dict:
        return {"url": url, "phase": phase, "error": error, "detail": detail}
