"""CSRF token extractor for POST form submissions.

Parses HTML to find hidden CSRF fields before submitting test payloads.
Supports Django, Laravel, Rails, ASP.NET, and generic csrf_token patterns.

Uses html.parser instead of regex to handle attribute-order variance and
multi-line input tags correctly.
"""

from __future__ import annotations

from html.parser import HTMLParser

CSRF_FIELD_NAMES = [
    "csrfmiddlewaretoken",         # Django
    "_token",                       # Laravel
    "authenticity_token",           # Rails
    "__RequestVerificationToken",   # ASP.NET
    "csrf_token",
    "csrf",
    "_csrf",
    "CSRFToken",
    "CSRF_TOKEN",
]

_NAME_SET = {n.lower() for n in CSRF_FIELD_NAMES}


class _CSRFParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.result: tuple[str, str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "input" or self.result:
            return
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        name = attr_map.get("name", "")
        if name.lower() not in _NAME_SET:
            return
        value = attr_map.get("value", "")
        if value:
            self.result = (name, value)


def extract_csrf(html: str) -> tuple[str, str] | None:
    """Scan HTML for a CSRF hidden input. Returns (field_name, token) or None."""
    parser = _CSRFParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    return parser.result
