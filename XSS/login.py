"""
Login 모듈 (현재 테스트용 mock)
실제 구현 시 이 파일의 get_auth() 내부를 교체

반환 형식:
    {"session_id": "...", "token": "..."}
    없는 값은 None
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

MOCK_PATH = Path(__file__).parent / "login_mock.json"


def get_auth() -> dict:
    """
    인증 정보 반환
    - 테스트: login_mock.json 읽기
    - 실제:   로그인 요청 후 session_id / token 파싱으로 교체
    """
    if not MOCK_PATH.exists():
        raise FileNotFoundError(
            f"login_mock.json 없음: {MOCK_PATH}\n"
            "login_mock.json을 생성하거나 get_auth()를 실제 로그인 로직으로 교체하세요."
        )

    with open(MOCK_PATH, "r", encoding="utf-8") as f:
        auth = json.load(f)

    logger.info(f"[login.py] 인증 정보 로드 완료 (mock): {MOCK_PATH}")
    return {
        "session_id": auth.get("session_id"),
        "token": auth.get("token"),
    }
