import os
import json
from pathlib import Path
from dotenv import load_dotenv
import anthropic
from .dashboard_renderer import DashboardRenderer
import re


class LLMReporter:
    def __init__(self):
        # project/llm/main.py 기준으로 project/ 루트 계산
        self.base_dir = Path(__file__).resolve().parent.parent

        # [수정] .env 로드 (경로 + 기본 로드 둘 다 수행)
        load_dotenv(self.base_dir / ".env", override=True)   # 명시적 경로
        load_dotenv()                         # fallback (실행 위치 기준)

        # [수정] 환경변수 읽고 공백 제거
        self.api_key = os.getenv("ANTHROPIC_API_KEY")
        self.model = os.getenv("MODEL_NAME")

        # [수정] None 방지 + strip 안전 처리
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY가 설정되지 않았습니다.")

        if not self.model:
            raise ValueError("MODEL_NAME이 설정되지 않았습니다.")

        self.api_key = self.api_key.strip()
        self.model = self.model.strip()

        # 디버깅 출력 (모델문제 확인용)
        #print(f"[DEBUG] MODEL_NAME = {self.model}")

        # 클라이언트 생성
        #dashboard_renderer.py 호출용 인스턴스 생성
        # base_dir은 project/ 루트를 넘겨 templates/, output/ 경로가 안정적으로 잡히게 함
        self.client = anthropic.Anthropic(api_key=self.api_key)
        self.renderer = DashboardRenderer(base_dir=self.base_dir)

    def load_prompt_template(self):
        prompt_path = self.base_dir / "prompt.txt"

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

    def build_prompt(self, scan_data: dict):
        prompt_template = self.load_prompt_template()

        sections = []

        if scan_data.get("nmap"):
            sections.append(
                "[Nmap 스캔 결과]\n"
                + json.dumps(scan_data["nmap"], indent=2, ensure_ascii=False)
            )

        if scan_data.get("fuzzer"):
            sections.append(
                "[Fuzzer 디렉토리 결과]\n"
                + json.dumps(scan_data["fuzzer"], indent=2, ensure_ascii=False)
            )

        if scan_data.get("crawler"):
            sections.append(
                "[Crawler 결과]\n"
                + json.dumps(scan_data["crawler"], indent=2, ensure_ascii=False)
            )

        combined_data = "\n\n".join(sections)

        # LLM이 Markdown 보고서가 아니라 JSON만 출력하도록 추가 지시를 붙임
        json_output_rule = """
[최종 출력 규칙 / STRICT JSON OUTPUT]
반드시 JSON 객체만 출력하라.
Markdown, 설명문, 코드블록(```json), 주석은 출력하지 마라.
출력 JSON은 아래 구조를 반드시 따른다.

{
  "summary": "전체 공격 표면 요약",
  "target": "스캔 대상",
  "scan_time": "스캔 시간",
  "stats": {
    "total": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "network": 0,
    "web": 0
  },
  "findings": [
    {
      "category": "Network | Web | Other",
      "title": "발견사항 제목",
      "risk": "HIGH | MEDIUM | LOW",
      "target": "IP:PORT 또는 URL",
      "evidence": "입력 JSON 기반 근거",
      "impact": "예상 영향",
      "recommendation": "권고사항"
    }
  ],
  "attack_paths": [
    {
      "title": "공격 경로 제목",
      "entry_point": "초기 진입점",
      "steps": ["단계1", "단계2"],
      "impact": "예상 영향",
      "likelihood": "HIGH | MEDIUM | LOW"
    }
  ],
  "limitations": [
    "입력 데이터만으로 확정할 수 없는 내용"
  ]
}
"""

        return f"{prompt_template}\n\n[스캔 데이터]\n{combined_data}"
    
    # Claude 응답에서 JSON 객체만 안전하게 파싱
    def parse_llm_json(self, response_text: str):
        """
        Claude가 원칙적으로 JSON만 반환해야 하지만,
        혹시 코드블록이나 앞뒤 설명이 섞인 경우를 대비해 JSON 객체 영역을 한 번 더 추출한다.
        """
        text = response_text.strip()

        # ```json ... ``` 형태 방어
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text)
            text = re.sub(r"\s*```$", "", text)
            text = text.strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # 앞뒤 설명이 섞인 경우 첫 { 부터 마지막 } 까지 추출
            start = text.find("{")
            end = text.rfind("}")

            if start != -1 and end != -1 and start < end:
                candidate = text[start:end + 1]
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    pass

            raise ValueError(
                "LLM 응답이 올바른 JSON 형식이 아닙니다. "
                "프롬프트의 JSON 출력 강제 조건을 확인하세요."
            )

    def generate_report_from_data(self, scan_data: dict):
        prompt = self.build_prompt(scan_data)

        response = self.client.messages.create(
            model=self.model.strip(),
            max_tokens=4096,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        response_text = response.content[0].text

        return self.parse_llm_json(response_text)

    # LLM 분석 JSON을 dashboard_renderer.py로 넘겨 HTML 생성
    def render_dashboard(self, report_data: dict, output_filename="dashboard.html"):
        return self.renderer.render_from_report_data(
            report_data=report_data,
            output_filename=output_filename
        )

    #  Core 연동용 함수
    # Core에서 scan_data dict를 넘기면 LLM 분석 → JSON 파싱 → HTML 렌더링까지 수행
    def generate_dashboard_from_data(self, scan_data: dict, output_filename="dashboard.html"):
        report_data = self.generate_report_from_data(scan_data)
        dashboard_path = self.render_dashboard(report_data, output_filename)

        return {
            "report_data": report_data,
            "dashboard_path": dashboard_path
        }
    
    # 로컬 테스트용 함수
    # scan_result.json 같은 파일을 읽어 LLM 분석 → HTML 렌더링까지 수행
    def generate_dashboard_from_scan_file(self, filepath: str, output_filename="dashboard.html"):
        scan_data = self.load_scan_result(filepath)
        return self.generate_dashboard_from_data(scan_data, output_filename)
    
""" # 핸들러 예시입니다. Core 연동 시 참고하세요.
if __name__ == "__main__":
    reporter = LLMReporter()

    # 로컬 테스트
    result = reporter.generate_dashboard_from_scan_file(
        "scan_result.json",
        "dashboard.html"
    )

    print(f"[+] 대시보드 저장 완료: {result['dashboard_path']}")
    print(json.dumps(result["report_data"], indent=2, ensure_ascii=False))

    # Core 연동 시에는 아래처럼 사용
    # result = reporter.generate_dashboard_from_data(scan_data)
"""
