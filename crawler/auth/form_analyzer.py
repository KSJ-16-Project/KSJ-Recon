"""
form_analyzer.py — 로그인 폼에서 username/password/submit 셀렉터 추론

입력: detector.py가 반환한 페이지 dict (`_login_form` 키 포함)
출력: FormSelectors (Playwright에서 page.fill/click에 바로 사용 가능)
"""

from __future__ import annotations

from .models import FormSelectors

# username 필드 추론 키워드 (영문 + 한국어, 모두 소문자 비교)
_USERNAME_KEYWORDS = (
    "user", "email", "mail", "login", "account",
    "userid", "username", "loginid",
    "아이디", "이메일", "계정",
)

# id 필드명에 자주 쓰이는 패턴 ("id" 단독은 노이즈 많아서 분리)
_ID_NAME_PATTERNS = ("_id", "id_", "userid", "loginid", "memberid")

# Submit 버튼/링크 셀렉터 (한국 사이트 + 다국어 대응)
# 한국 사이트는 <a onclick="chk_login()">로그인</a> 같은 패턴이 흔함
_SUBMIT_SELECTOR = (
    "button[type=submit], input[type=submit], "
    "button:has-text('로그인'), a:has-text('로그인'), [role=button]:has-text('로그인'), "
    "button:has-text('Login'), a:has-text('Login'), "
    "button:has-text('Sign in'), button:has-text('Log in')"
)


def analyze_login_form(page: dict) -> FormSelectors:
    """
    로그인 폼에서 셀렉터 3종을 추론한다.

    Args:
        page: detector.find_login_page() 반환값
              (`_login_form` 키에 매칭된 폼이 들어 있음)

    Raises:
        ValueError: page에 _login_form이 없거나 password 필드가 없을 때
    """
    form = page.get("_login_form")
    if not form:
        raise ValueError("page에 _login_form 키가 없음 — detector.find_login_page() 출력만 입력 가능")

    fields = form.get("fields", [])

    password_field = _find_password_field(fields)
    if password_field is None:
        raise ValueError("password 필드를 찾을 수 없음")

    username_field = _find_username_field(fields, password_field)
    if username_field is None:
        raise ValueError("username 필드를 찾을 수 없음")

    return FormSelectors(
        username=_to_selector(username_field),
        password=_to_selector(password_field),
        submit=_SUBMIT_SELECTOR,
    )


# ---------------------------------------------------------------------------
# 내부 헬퍼
# ---------------------------------------------------------------------------

def _find_password_field(fields: list[dict]) -> dict | None:
    for f in fields:
        if f.get("type") == "password":
            return f
    return None


def _find_username_field(fields: list[dict], password_field: dict) -> dict | None:
    """
    username 필드 추론 (우선순위):
      1. type=email
      2. name/id/placeholder/aria_label에 키워드 포함
      3. 폼 내에서 password 필드 직전의 input
      4. 폴백: 첫 번째 텍스트/이메일/빈타입 input
    """
    text_like = [
        f for f in fields
        if f.get("type") in ("text", "email", "tel", "")
    ]
    if not text_like:
        return None

    # 1순위: type=email
    for f in text_like:
        if f.get("type") == "email":
            return f

    # 2순위: 키워드 매칭
    for f in text_like:
        haystack = " ".join([
            (f.get("name") or "").lower(),
            (f.get("id") or "").lower(),
            (f.get("placeholder") or "").lower(),
            (f.get("aria_label") or "").lower(),
        ])
        if not haystack.strip():
            continue
        if any(kw in haystack for kw in _USERNAME_KEYWORDS):
            return f
        if any(p in haystack for p in _ID_NAME_PATTERNS):
            return f

    # 3순위: password 필드 직전 input
    try:
        pwd_index = fields.index(password_field)
        for i in range(pwd_index - 1, -1, -1):
            if fields[i] in text_like:
                return fields[i]
    except ValueError:
        pass

    # 4순위: 첫 번째 텍스트 input
    return text_like[0]


def _to_selector(field: dict) -> str:
    """
    필드 메타데이터에서 가장 안정적인 CSS 셀렉터를 만든다.
    우선순위: name > id > placeholder > type별 첫 번째 매칭
    React SPA처럼 name이 없는 폼도 placeholder로 폴백.
    """
    name = field.get("name") or ""
    if name:
        return f"input[name='{_escape(name)}']"

    id_attr = field.get("id") or ""
    if id_attr:
        return f"#{_escape(id_attr)}"

    # React SPA 폴백: placeholder 기반 셀렉터
    placeholder = field.get("placeholder") or ""
    if placeholder:
        return f"input[placeholder='{_escape(placeholder)}']"

    # 최종 폴백: 타입 기반 (단일 폼이면 보통 작동)
    ftype = field.get("type") or "text"
    if ftype == "password":
        return "input[type=password]"
    if ftype == "email":
        return "input[type=email]"
    return "input[type=text]"


def _escape(value: str) -> str:
    """CSS 셀렉터 내부 작은따옴표 이스케이프."""
    return value.replace("\\", "\\\\").replace("'", "\\'")
