import json
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape


class DashboardRenderer:
    def __init__(self, base_dir=None):
        #base_dir은 project 루트로 받는 것을 기준으로 함
        # llm.py에서 DashboardRenderer(base_dir=self.base_dir) 형태로 호출
        self.base_dir = Path(base_dir).resolve() if base_dir else Path(__file__).resolve().parent.parent

        #"../templates" 대신 project/templates 로 명확하게 고정
        self.template_dir = Path(__file__).resolve().parent / "templates"
        print(f"[DEBUG] TEMPLATE_DIR = {self.template_dir}")
        print(f"[DEBUG] EXISTS = {(self.template_dir / 'dashboard.html').exists()}")
        print(f"[DEBUG] FILES = {list(self.template_dir.glob('*'))}")
        self.env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=select_autoescape(["html", "xml"])
        )

    # LLM이 stats를 누락하거나 잘못 준 경우를 대비해 findings 기준으로 재계산
    def build_stats_from_findings(self, findings):
        return {
            "total": len(findings),
            "high": sum(1 for item in findings if item.get("risk") == "HIGH"),
            "medium": sum(1 for item in findings if item.get("risk") == "MEDIUM"),
            "low": sum(1 for item in findings if item.get("risk") == "LOW"),
            "network": sum(1 for item in findings if item.get("category") == "Network"),
            "web": sum(1 for item in findings if item.get("category") == "Web"),
        }

    # renderer 입력 검증 및 기본값 보정
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
                "impact": item.get("impact", "-"),
                "recommendation": item.get("recommendation", "-")
            })

        stats = report_data.get("stats") or self.build_stats_from_findings(normalized_findings)

        # stats가 있어도 findings 기준 값이 더 신뢰 가능하므로 누락값 보정
        calculated = self.build_stats_from_findings(normalized_findings)
        for key, value in calculated.items():
            stats.setdefault(key, value)

        return {
            "summary": report_data.get("summary", "-"),
            "target": report_data.get("target", "-"),
            "scan_time": report_data.get("scan_time", "-"),
            "stats": stats,
            "findings": normalized_findings,
            "attack_paths": report_data.get("attack_paths") or [],
            "limitations": report_data.get("limitations") or []
        }

    # LLM이 만든 report JSON을 받아 HTML 대시보드 생성
    def render_from_report_data(self, report_data: dict, output_filename="dashboard.html"):
        report = self.normalize_report_data(report_data)

        template = self.env.get_template("dashboard.html")

        html = template.render(
            summary=report["summary"],
            target=report["target"],
            scan_time=report["scan_time"],
            stats=report["stats"],
            findings=report["findings"],
            findings_json=json.dumps(report["findings"], ensure_ascii=False),
            attack_paths=report["attack_paths"],
            limitations=report["limitations"]
        )

        output_dir = self.base_dir / "output"
        output_dir.mkdir(exist_ok=True)

        output_path = output_dir / output_filename
        output_path.write_text(html, encoding="utf-8")

        return output_path

