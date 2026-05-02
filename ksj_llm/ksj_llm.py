import os
import json
from pathlib import Path
from dotenv import load_dotenv
import anthropic


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

        # [수정] 클라이언트 생성
        self.client = anthropic.Anthropic(api_key=self.api_key)

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

        return f"{prompt_template}\n\n[스캔 데이터]\n{combined_data}"

    def generate_report_from_data(self, scan_data: dict):
        prompt = self.build_prompt(scan_data)

        response = self.client.messages.create(
            model=self.model.strip(),
            max_tokens=4096,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        return response.content[0].text

    def generate_report_from_scan_file(self, filepath: str):
        """
        테스트 단계용
        통합 scan JSON 파일 1개를 읽고 보고서를 생성
        """
        scan_data = self.load_scan_result(filepath)
        return self.generate_report_from_data(scan_data)

    def save_report(self, report_text, filename="report.md"):
        output_dir = self.base_dir / "output"
        output_dir.mkdir(exist_ok=True)

        output_path = output_dir / filename

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_text)

        print(f"[+] 보고서 저장 완료: {output_path}")
        return output_path
""" # 핸들러 입니다 연동에 참고해주세요
if __name__ == "__main__":
    reporter = LLMReporter()

    report = reporter.generate_report_from_scan_file("scan_result.json")
    #reporter.generate_report_from_scan_file 로컬파일 기준 보고서 작성시 파일을 읽는 함수
    report = reporter.generate_report_from_data(scan_data)
    # 코어 연동간에서는 reporter.generate_report_from_data 함수를 사용하시면 됩니다
    # 보고서 파일 세이브는 ../output/에 생성됩니다
    # 생성 보고서 git에 공유 안되게하려면 .gitignore 파일에 output/ 가 등록되어 있어야합니다
    # API 키 노출 안되게 조심해주세요

    saved_path = reporter.save_report(report)
    현재는 모듈 내부에 save 함수를 구현을 해놨지만 나중에 코어단에서 save로직을 돌려야 할듯 합니다
"""