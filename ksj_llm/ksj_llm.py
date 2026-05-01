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
당신은 시니어 모의해킹 전문가(Penetration Tester)이자 보안 분석가이다.

[목표 / GOAL]
여러 Recon 스캔 결과(JSON)를 분석하여
공격자 관점의 공격 표면(Attack Surface) 보고서를 생성하라.

---

[분석 요구사항 / CRITICAL TASKS]

1. 노출된 서비스 식별 (Identify exposed services)
   - 열린 포트 및 서비스 분석
   - SMB, RPC, HTTP, WebSocket 등 주요 서비스 집중 분석
   - unknown 서비스는 반드시 강조

2. 웹 공격 표면 식별 (Identify web attack surface)
   - 디렉터리 및 엔드포인트 분석
   - 민감 경로 및 공격 진입점 탐색

3. 스캔 결과 상관관계 분석 (Correlate findings)
   - 포트 정보와 웹 경로를 연결
   - 동일 서비스 기반 공격 가능성 도출

4. 현실적인 공격 시나리오 생성 (Build attack scenarios)
   - 여러 발견사항을 조합하여 공격 흐름 구성
   - 실제 공격자가 사용할 수 있는 경로로 작성

5. 우선순위 평가 (Prioritize findings)
   - 가장 먼저 악용 가능한 항목 식별
   - 공격 가능성 및 영향도 기반 판단

6. 이상 징후 탐지 (Highlight anomalies)
   - 다수의 unknown 포트
   - 비정상 서비스 또는 특이 패턴

---

[출력 보고서 형식 / OUTPUT FORMAT]

## 보안 취약점 분석 보고서
- 스캔 대상 및 스캔 시간
- 발견된 서비스 목록 (포트 / 프로토콜 / 버전)
- 노출된 디렉토리 및 경로
- 취약점 목록 (CVE, CVSS 점수)
- 위험도 분류 (High / Medium / Low)
- 권고사항

---

[중요 규칙 / IMPORTANT]

- 반드시 입력 데이터 기반으로만 분석 (추측 금지)
- 허위 취약점 생성 금지 (No hallucination)
- 공격자 관점에서 분석할 것
- 가능한 간결하지만 기술적으로 작성

---
"""

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