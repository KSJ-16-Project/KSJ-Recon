import json
import anthropic
from datetime import datetime


class LLMReporter:
    def __init__(self, api_key=""):
        self.client = anthropic.Anthropic(api_key=api_key)

    def load_scan_results(self, filepaths: dict):
        # {"nmap": "nmap_result.json", "fuzzer": "fuzzer_directory.json", "crawler": "crawler_result.json"}
        data = {}
        for key, path in filepaths.items():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data[key] = json.load(f)
            except FileNotFoundError:
                data[key] = None
        return data

    def build_prompt(self, scan_data: dict):
        sections = []

        if scan_data.get("nmap"):
            sections.append(f"[Nmap 스캔 결과]\n{json.dumps(scan_data['nmap'], indent=2, ensure_ascii=False)}")

        if scan_data.get("fuzzer"):
            sections.append(f"[Fuzzer 디렉토리 결과]\n{json.dumps(scan_data['fuzzer'], indent=2, ensure_ascii=False)}")

        if scan_data.get("crawler"):
            sections.append(f"[Crawler 결과]\n{json.dumps(scan_data['crawler'], indent=2, ensure_ascii=False)}")

        combined = "\n\n".join(sections)

        return f"""다음은 보안 스캔 결과입니다.
이 결과를 종합 분석하여 보안 취약점 보고서를 작성해주세요.

{combined}

[보고서 형식]
## 보안 취약점 분석 보고서
- 스캔 대상 및 스캔 시간
- 발견된 서비스 목록 (포트 / 프로토콜 / 버전)
- 노출된 디렉토리 및 경로
- 취약점 목록 (CVE, CVSS 점수)
- 위험도 분류 (High / Medium / Low)
- 권고사항"""

    def generate_report(self, scan_data: dict):
        message = self.client.messages.create(
            model="claude-opus-4-6",
            max_tokens=2048,
            messages=[
                {"role": "user", "content": self.build_prompt(scan_data)}
            ]
        )
        return message.content[0].text

    def save_report(self, report_text, filename="report.md"):
        with open(filename, "w", encoding="utf-8") as f:
            f.write(report_text)

    def run(self, filepaths: dict):
        scan_data = self.load_scan_results(filepaths)
        report = self.generate_report(scan_data)
        self.save_report(report)
        return report


# 코어 연동 참고용
'''
if __name__ == "__main__":
    reporter = LLMReporter(api_key="API_KEY")
    reporter.run({
        "nmap": "nmap_result.json",
        "fuzzer": "fuzzer_directory.json",
        "crawler": "crawler_result.json"
    })
'''