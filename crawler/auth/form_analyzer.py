"""Infer Playwright selectors for a detected login form."""

from __future__ import annotations

from .models import FormSelectors


_USERNAME_KEYWORDS = (
    "user",
    "email",
    "mail",
    "login",
    "account",
    "userid",
    "username",
    "loginid",
    "id",
)

_ID_NAME_PATTERNS = ("_id", "id_", "userid", "loginid", "memberid")

_SUBMIT_SELECTOR = (
    "button[type=submit], input[type=submit], "
    "button:has-text('로그인'), a:has-text('로그인'), "
    "[role=button]:has-text('로그인'), "
    "button:has-text('Login'), a:has-text('Login'), "
    "button:has-text('Sign in'), a:has-text('Sign in'), "
    "button:has-text('Log in'), a:has-text('Log in'), "
    "[role=button]:has-text('Login'), [role=button]:has-text('Sign in')"
)


def analyze_login_form(page: dict) -> FormSelectors:
    """Return username, password, and submit selectors for Playwright."""
    form = page.get("_login_form")
    if not form:
        raise ValueError("page must contain _login_form from find_login_page()")

    fields = form.get("fields", [])
    password_field = _find_password_field(fields)
    if password_field is None:
        raise ValueError("password field not found")

    username_field = _find_username_field(fields, password_field)
    if username_field is None:
        raise ValueError("username field not found")

    return FormSelectors(
        username=_to_selector(username_field),
        password=_to_selector(password_field),
        submit=_SUBMIT_SELECTOR,
    )


def _field_type(field: dict) -> str:
    return (field.get("type") or field.get("field_type") or "text").lower()


def _find_password_field(fields: list[dict]) -> dict | None:
    for field in fields:
        if _field_type(field) == "password":
            return field
    return None


def _find_username_field(fields: list[dict], password_field: dict) -> dict | None:
    text_like = [
        field
        for field in fields
        if _field_type(field) in ("text", "email", "tel", "search", "")
    ]
    if not text_like:
        return None

    for field in text_like:
        if _field_type(field) == "email":
            return field

    for field in text_like:
        haystack = " ".join(
            [
                (field.get("name") or "").lower(),
                (field.get("id") or "").lower(),
                (field.get("placeholder") or "").lower(),
                (field.get("aria_label") or "").lower(),
            ]
        )
        if any(keyword in haystack for keyword in _USERNAME_KEYWORDS):
            return field
        if any(pattern in haystack for pattern in _ID_NAME_PATTERNS):
            return field

    try:
        password_index = fields.index(password_field)
        for index in range(password_index - 1, -1, -1):
            if fields[index] in text_like:
                return fields[index]
    except ValueError:
        pass

    return text_like[0]


def _to_selector(field: dict) -> str:
    name = field.get("name") or ""
    if name:
        return f"input[name='{_escape(name)}']"

    field_id = field.get("id") or ""
    if field_id:
        return f"#{_escape(field_id)}"

    placeholder = field.get("placeholder") or ""
    if placeholder:
        return f"input[placeholder='{_escape(placeholder)}']"

    field_type = _field_type(field)
    if field_type == "password":
        return "input[type=password]"
    if field_type == "email":
        return "input[type=email]"
    return "input[type=text]"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")
