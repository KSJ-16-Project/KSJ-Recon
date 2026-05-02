"""detector.find_login_page 단위 테스트 — 모의 페이지 데이터 사용."""

from crawler.auth.detector import find_login_page


def _field(name="", type_="text", **kw):
    return {
        "name": name,
        "type": type_,
        "id": kw.get("id", ""),
        "placeholder": kw.get("placeholder", ""),
        "aria_label": kw.get("aria_label", ""),
        "value": kw.get("value", ""),
        "required": kw.get("required", False),
    }


def _form(method="POST", fields=None, action="/auth"):
    return {
        "action": action,
        "method": method,
        "enctype": "",
        "fields": fields or [],
    }


def _page(url, forms):
    return {"url": url, "forms": forms}


# ---------------------------------------------------------------------------
# 매칭되어야 하는 케이스
# ---------------------------------------------------------------------------

def test_basic_login_form():
    """전형적인 로그인 폼."""
    pages = [
        _page("https://x.com/login", [
            _form(fields=[
                _field("user", "text"),
                _field("pwd", "password"),
            ])
        ])
    ]
    result = find_login_page(pages)
    assert result is not None
    assert result["url"] == "https://x.com/login"
    assert "_login_form" in result


def test_login_form_with_csrf_token():
    """CSRF hidden 필드가 있어도 매칭."""
    pages = [
        _page("https://x.com/login", [
            _form(fields=[
                _field("csrf", "hidden", value="abc"),
                _field("email", "email"),
                _field("password", "password"),
            ])
        ])
    ]
    assert find_login_page(pages) is not None


def test_korean_field_names():
    """한국식 비표준 필드명도 매칭 (placeholder만 한글)."""
    pages = [
        _page("/", [
            _form(fields=[
                _field("mb_id", "text", placeholder="아이디를 입력하세요"),
                _field("mb_password", "password", placeholder="비밀번호"),
            ])
        ])
    ]
    assert find_login_page(pages) is not None


# ---------------------------------------------------------------------------
# 매칭되면 안 되는 케이스
# ---------------------------------------------------------------------------

def test_search_form_get_method():
    """GET 메서드의 검색 폼은 제외."""
    pages = [
        _page("/", [_form(method="GET", fields=[_field("q", "text")])])
    ]
    assert find_login_page(pages) is None


def test_password_change_form():
    """password 필드 2개 이상이면 비밀번호 변경 폼으로 간주, 제외."""
    pages = [
        _page("/account", [
            _form(fields=[
                _field("old_pwd", "password"),
                _field("new_pwd", "password"),
                _field("confirm_pwd", "password"),
            ])
        ])
    ]
    assert find_login_page(pages) is None


def test_signup_form_too_many_fields():
    """제출 가능한 필드 수가 임계값(6) 초과면 회원가입으로 간주, 제외."""
    pages = [
        _page("/signup", [
            _form(fields=[
                _field("email", "email"),
                _field("password", "password"),
                _field("name", "text"),
                _field("phone", "tel"),
                _field("address", "text"),
                _field("birth", "text"),
                _field("zip", "text"),
                _field("company", "text"),
            ])
        ])
    ]
    assert find_login_page(pages) is None


def test_no_password_field():
    """password 필드 없으면 로그인 폼 아님."""
    pages = [
        _page("/contact", [
            _form(fields=[
                _field("name", "text"),
                _field("message", "text"),
            ])
        ])
    ]
    assert find_login_page(pages) is None


def test_no_text_input():
    """password만 있고 텍스트 input 없으면 로그인 폼 아님 (이상한 케이스 방어)."""
    pages = [
        _page("/", [
            _form(fields=[_field("pwd", "password")])
        ])
    ]
    assert find_login_page(pages) is None


def test_empty_pages():
    """빈 페이지 목록."""
    assert find_login_page([]) is None


def test_pages_without_forms():
    """폼 없는 페이지들."""
    pages = [
        _page("/about", []),
        _page("/contact", []),
    ]
    assert find_login_page(pages) is None


# ---------------------------------------------------------------------------
# 다중 페이지 / 다중 폼
# ---------------------------------------------------------------------------

def test_multiple_pages_returns_first_match():
    """여러 페이지 중 첫 번째 매칭되는 것 반환."""
    pages = [
        _page("/about", []),
        _page("/login", [
            _form(fields=[_field("u", "text"), _field("p", "password")])
        ]),
        _page("/admin/login", [
            _form(fields=[_field("u", "text"), _field("p", "password")])
        ]),
    ]
    result = find_login_page(pages)
    assert result["url"] == "/login"


def test_page_with_search_and_login_forms():
    """한 페이지에 검색 폼 + 로그인 폼 같이 있으면 로그인 폼이 매칭됨."""
    pages = [
        _page("/", [
            _form(method="GET", fields=[_field("q", "text")]),
            _form(method="POST", fields=[
                _field("user", "text"),
                _field("pwd", "password"),
            ]),
        ])
    ]
    result = find_login_page(pages)
    assert result is not None
    # 매칭된 폼이 로그인 폼인지 확인
    assert any(f["type"] == "password" for f in result["_login_form"]["fields"])
