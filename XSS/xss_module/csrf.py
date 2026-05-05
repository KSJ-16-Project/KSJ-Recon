"""CSRF token extractor for POST form submissions.

Parses HTML to find hidden CSRF fields before submitting test payloads.
Supports Django, Laravel, Rails, ASP.NET, and generic csrf_token patterns.
"""

from __future__ import annotations

import re

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
_INPUT_RE = re.compile(r"<input\b[^>]*/?>", re.IGNORECASE | re.DOTALL)
_NAME_RE  = re.compile(r'\bname=["\']([^"\']+)["\']', re.IGNORECASE)
_VALUE_RE = re.compile(r'\bvalue=["\']([^"\']*)["\']', re.IGNORECASE)


def extract_csrf(html: str) -> tuple[str, str] | None:
    """Scan HTML for a CSRF hidden input. Returns (field_name, token) or None."""
    for tag in _INPUT_RE.finditer(html):
        text = tag.group(0)
        name_m = _NAME_RE.search(text)
        if not name_m:
            continue
        name = name_m.group(1)
        if name.lower() not in _NAME_SET:
            continue
        value_m = _VALUE_RE.search(text)
        if not value_m or not value_m.group(1):
            continue
        return name, value_m.group(1)
    return None
