"""form_analyzer.analyze_login_form 단위 테스트."""

import pytest

from crawler.auth.form_analyzer import analyze_login_form


def _field(name="", type_="text", **kw):
    return {
        "name": name, "type": type_,
        "id": kw.get("id", ""),
        "placeholder": kw.get("placeholder", ""),
        "aria_label": kw.get("aria_label", ""),
        "value": kw.get("value", ""),
        "required": kw.get("required", False),
    }


def _login_page(fields):
    """detector 출력 형태 (_login_form 포함) 모방."""
    form = {"action": "/auth", "method": "POST", "enctype": "", "fields": fields}
    return {"url": "/login", "forms": [form], "_login_form": form}


# ---------------------------------------------------------------------------
# username 추론 우선순위
# ---------------------------------------------------------------------------

def test_email_type_takes_priority():
    """type=email은 다른 키워드보다 우선."""
    page = _login_page([
        _field("randomname", "text", placeholder="user id"),  # 키워드 매칭됨
        _field("contact", "email"),                           # 하지만 email이 우선
        _field("pwd", "password"),
    ])
    sel = analyze_login_form(page)
    assert sel.username == "input[name='contact']"


def test_keyword_match_in_name():
    """name 속성에 키워드 포함."""
    page = _login_page([
        _field("user_id", "text"),
        _field("pwd", "password"),
    ])
    sel = analyze_login_form(page)
    assert sel.username == "input[name='user_id']"


def test_keyword_match_in_placeholder_korean():
    """한국어 placeholder 매칭."""
    page = _login_page([
        _field("mb_input", "text", placeholder="아이디를 입력하세요"),
        _field("mb_pwd", "password"),
    ])
    sel = analyze_login_form(page)
    assert sel.username == "input[name='mb_input']"


def test_keyword_match_in_id():
    """id 속성에 키워드 포함."""
    page = _login_page([
        _field("xyz", "text", id="loginId"),
        _field("pwd", "password"),
    ])
    sel = analyze_login_form(page)
    assert sel.username == "input[name='xyz']"


def test_keyword_match_in_aria_label():
    """aria-label에 키워드."""
    page = _login_page([
        _field("xyz", "text", aria_label="이메일 주소"),
        _field("pwd", "password"),
    ])
    sel = analyze_login_form(page)
    assert sel.username == "input[name='xyz']"


def test_password_predecessor_fallback():
    """키워드 매칭 실패 시 password 필드 직전 input."""
    page = _login_page([
        _field("hidden_csrf", "hidden", value="abc"),
        _field("xxx", "text"),  # 키워드 없음
        _field("pwd", "password"),
    ])
    sel = analyze_login_form(page)
    assert sel.username == "input[name='xxx']"


def test_first_text_input_fallback():
    """모든 휴리스틱 실패 시 첫 번째 텍스트 input."""
    page = _login_page([
        _field("aaa", "text"),
        _field("bbb", "text"),
        _field("pwd", "password"),
    ])
    sel = analyze_login_form(page)
    # password 직전 = "bbb", 그게 우선됨
    assert sel.username == "input[name='bbb']"


# ---------------------------------------------------------------------------
# 셀렉터 생성
# ---------------------------------------------------------------------------

def test_selector_uses_id_when_name_missing():
    """name 없으면 id 기반 셀렉터."""
    page = _login_page([
        _field("", "text", id="userid", placeholder="아이디"),
        _field("pwd", "password"),
    ])
    sel = analyze_login_form(page)
    assert sel.username == "#userid"


def test_password_selector():
    """password 필드 셀렉터는 항상 name 우선."""
    page = _login_page([
        _field("user", "text"),
        _field("user_password", "password"),
    ])
    sel = analyze_login_form(page)
    assert sel.password == "input[name='user_password']"


def test_submit_selector_includes_korean():
    """submit 셀렉터에 한국어 '로그인' 텍스트 포함."""
    page = _login_page([
        _field("u", "text"),
        _field("p", "password"),
    ])
    sel = analyze_login_form(page)
    assert "로그인" in sel.submit
    assert "Login" in sel.submit


# ---------------------------------------------------------------------------
# 에러 케이스
# ---------------------------------------------------------------------------

def test_raises_when_no_login_form_key():
    """detector를 거치지 않은 페이지는 거부."""
    page = {"url": "/", "forms": [{"fields": []}]}  # _login_form 없음
    with pytest.raises(ValueError, match="_login_form"):
        analyze_login_form(page)


def test_raises_when_no_password_field():
    page = _login_page([_field("user", "text")])
    with pytest.raises(ValueError, match="password"):
        analyze_login_form(page)


def test_raises_when_no_username_candidate():
    """텍스트/이메일 input이 전혀 없으면 에러."""
    page = _login_page([
        _field("csrf", "hidden"),
        _field("pwd", "password"),
    ])
    with pytest.raises(ValueError, match="username"):
        analyze_login_form(page)


# ---------------------------------------------------------------------------
# 셀렉터 이스케이프
# ---------------------------------------------------------------------------

def test_selector_escapes_single_quote():
    """name에 작은따옴표가 있으면 이스케이프."""
    page = _login_page([
        _field("user'name", "text"),
        _field("pwd", "password"),
    ])
    sel = analyze_login_form(page)
    assert "\\'" in sel.username
