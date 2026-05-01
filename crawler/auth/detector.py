"""
detector.py — 1차 크롤 결과에서 로그인 페이지 식별

입력 포맷 (담당자 C와 합의된 v1.0):
{
    "url": str,
    "forms": [
        {
            "action": str, "method": str, "enctype": str,
            "fields": [
                {"name", "type", "id", "placeholder", "aria_label", "value", "required"}
            ]
        }
    ]
}
"""

from __future__ import annotations

from typing import Optional

# 회원가입 폼 판별 임계값 (필드 수가 이보다 많으면 회원가입으로 간주)
_SIGNUP_FIELD_THRESHOLD = 6

# 폼 제출에 사용되지 않는 필드 타입 (필드 수 카운트에서 제외)
_NON_SUBMITTABLE_TYPES = {"hidden", "submit", "button", "image", "reset"}


def find_login_page(pages: list[dict]) -> Optional[dict]:
    """
    1차 크롤 결과에서 로그인 페이지를 식별한다.

    판별 기준 (모두 만족):
      1. 폼에 type=password 필드가 정확히 1개 존재
      2. 같은 폼에 텍스트/이메일 타입 input이 1개 이상 존재
      3. 폼이 POST 메서드 (GET은 검색창일 가능성)
      4. 제출 가능한 필드 수가 임계값(6) 이하 (회원가입 제외)

    Returns:
        매칭된 페이지 dict, 또는 None
        반환되는 dict는 입력 그대로이므로 호출자가 form_analyzer로 넘길 수 있음
    """
    for page in pages:
        forms = page.get("forms", [])
        for form in forms:
            if _is_login_form(form):
                # 매칭된 폼을 page에 표시해서 반환 (form_analyzer가 활용)
                return {**page, "_login_form": form}
    return None


def _is_login_form(form: dict) -> bool:
    """
    단일 폼이 로그인 폼인지 판별.

    method 검사는 의도적으로 제외 — React/Vue SPA는 폼에 method 속성을 안 붙이고
    onSubmit 핸들러로 처리하므로 method='get' (기본값)으로 보일 수 있음.
    검색 폼은 password 필드가 없어서 자동으로 걸러짐.
    """
    fields = form.get("fields", [])

    password_count = sum(1 for f in fields if f.get("type") == "password")
    if password_count != 1:
        # 0개: 로그인 폼 아님
        # 2개 이상: 비밀번호 변경/회원가입
        return False

    # 텍스트/이메일 타입 input이 1개 이상 있어야 username 입력 가능
    text_like = sum(
        1 for f in fields
        if f.get("type") in ("text", "email", "tel", "")
    )
    if text_like < 1:
        return False

    # 회원가입 폼 배제 (제출 가능 필드 수 기준)
    submittable = [
        f for f in fields
        if f.get("type") not in _NON_SUBMITTABLE_TYPES
    ]
    if len(submittable) > _SIGNUP_FIELD_THRESHOLD:
        return False

    return True
