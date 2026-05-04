import os
import json
import re
from pathlib import Path
from dotenv import load_dotenv
import anthropic


class LLMPreprocessor:
    def __init__(self):
        # project/ksj_llm/preprocessor.py 기준 project 루트 계산
        self.base_dir = Path(__file__).resolve().parent.parent

        # project/.env 로드
        load_dotenv(self.base_dir / ".env", override=True)
        load_dotenv()

        self.api_key = os.getenv("ANTHROPIC_API_KEY")
        self.model = os.getenv("MODEL_NAME")

        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY가 설정되지 않았습니다.")

        if not self.model:
            raise ValueError("MODEL_NAME이 설정되지 않았습니다.")

        self.api_key = self.api_key.strip()
        self.model = self.model.strip()

        self.client = anthropic.Anthropic(api_key=self.api_key)

    def load_prompt_template(self):
        # [중요] 네가 지정한 경로
        prompt_path = self.base_dir / "prompts" / "preprocess_pormpt.txt"

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

    def build_prompt(self, scan_data: dict):
        prompt_template = self.load_prompt_template()

        safe_scan_data = self.make_json_safe(scan_data)

        combined_data = json.dumps(
            safe_scan_data,
            indent=2,
            ensure_ascii=False
        )

        json_output_rule = """
[최종 출력 규칙 / STRICT JSON OUTPUT]
반드시 JSON 객체만 출력하라.
Markdown, 설명문, 코드블록(```json), 주석은 출력하지 마라.
JSON 문법을 엄격히 지켜라.
객체나 배열의 마지막 항목 뒤에 trailing comma를 절대 넣지 마라.
모든 key와 문자열 value는 반드시 큰따옴표(")로 감싸라.
Python dict 문법이 아니라 순수 JSON 문법으로 출력하라.
None, True, False 대신 null, true, false를 사용하라.
"""

        return f"{prompt_template}\n\n{json_output_rule}\n\n[스캔 데이터]\n{combined_data}"

    def parse_llm_json(self, response_text: str):
        """
        Claude 응답을 JSON dict로 변환.
        코드블록, 앞뒤 설명, trailing comma를 방어적으로 처리.
        """
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
            max_tokens=4096,
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
사용 예시:

from ksj_llm.preprocessor import LLMPreprocessor

preprocessor = LLMPreprocessor()

# Core 연동
pre_data = preprocessor.generate_preprocess_data(results)

sql_data = pre_data["sql_data"]
xss_data = pre_data["xss_data"]
filedown_data = pre_data["filedown_data"]
ssrf_data = pre_data["ssrf_data"]

# 로컬 테스트
# pre_data = preprocessor.generate_preprocess_data_from_file("scan_result.json")
"""