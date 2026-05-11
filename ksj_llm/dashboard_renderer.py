import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


class DashboardRenderer:
    def __init__(self, base_dir=None):
        self.base_dir = Path(base_dir).resolve() if base_dir else Path(__file__).resolve().parent.parent
        self.template_dir = Path(__file__).resolve().parent / "templates"
        self.env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=select_autoescape(["html", "xml"])
        )

    def build_stats_from_findings(self, findings):
        return {
            "total": len(findings),
            "high": sum(1 for item in findings if item.get("risk") == "HIGH"),
            "medium": sum(1 for item in findings if item.get("risk") == "MEDIUM"),
            "low": sum(1 for item in findings if item.get("risk") == "LOW"),
            "network": sum(1 for item in findings if item.get("category") == "Network"),
            "web": sum(1 for item in findings if item.get("category") == "Web"),
            "sqli": sum(1 for item in findings if item.get("category") == "SQLi"),
            "xss": sum(1 for item in findings if item.get("category") == "XSS"),
            "filedownload": sum(1 for item in findings if item.get("category") == "FileDownload"),
            "ssrf": sum(1 for item in findings if item.get("category") == "SSRF"),
            "other": sum(1 for item in findings if item.get("category") == "Other"),
        }

    def normalize_report_data(self, report_data: dict):
        findings = report_data.get("findings") or []

        normalized_findings = []
        for item in findings:
            normalized_findings.append({
                "category": item.get("category", "Other"),
                "title": item.get("title", "-"),
                "risk": item.get("risk", "LOW"),
                "target": item.get("target", "-"),
                "evidence": item.get("evidence", "-"),
                "payload_example": item.get("payload_example", ""),
                "impact": item.get("impact", "-"),
                "recommendation": item.get("recommendation", "-")
            })

        return {
            "summary": report_data.get("summary", "-"),
            "target": report_data.get("target", "-"),
            "scan_time": report_data.get("scan_time", "-"),
            "stats": self.build_stats_from_findings(normalized_findings),
            "findings": normalized_findings,
            "attack_paths": report_data.get("attack_paths") or [],
            "limitations": report_data.get("limitations") or []
        }

    def render_from_report_data(self, report_data: dict, output_filename="dashboard.html"):
        report = self.normalize_report_data(report_data)
        template = self.env.get_template("dashboard.html")

        html = template.render(
            summary=report["summary"],
            target=report["target"],
            scan_time=report["scan_time"],
            stats=report["stats"],
            findings=report["findings"],
            findings_json=json.dumps(report["findings"], ensure_ascii=False).replace("</", "<\\/"),
            attack_paths=report["attack_paths"],
            limitations=report["limitations"]
        )

        output_dir = self.base_dir / "output"
        output_dir.mkdir(exist_ok=True)

        output_path = output_dir / output_filename
        output_path.write_text(html, encoding="utf-8")

        return output_path
