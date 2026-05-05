"""
담당자 C의 parse.py 임시 대체.
rendered_html → v1.0 스펙 페이지 dict 변환만 담당.
"""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin


class _FormExtractor(HTMLParser):
    def __init__(self, page_url: str):
        super().__init__()
        self.page_url = page_url
        self.forms: list[dict] = []
        self._cur_form: dict | None = None

    def handle_starttag(self, tag: str, attrs):
        attr = dict(attrs)

        if tag == "form":
            action = attr.get("action") or self.page_url
            self._cur_form = {
                "action": urljoin(self.page_url, action),
                "method": (attr.get("method") or "GET").upper(),
                "enctype": attr.get("enctype") or "",
                "fields": [],
            }
        elif tag in ("input", "textarea", "select") and self._cur_form is not None:
            ftype = (attr.get("type") or "text").lower() if tag == "input" else tag
            self._cur_form["fields"].append({
                "name": attr.get("name") or "",
                "type": ftype,
                "id": attr.get("id") or "",
                "placeholder": attr.get("placeholder") or "",
                "aria_label": attr.get("aria-label") or "",
                "value": attr.get("value") or "",
                "required": "required" in attr,
            })

    def handle_endtag(self, tag: str):
        if tag == "form" and self._cur_form is not None:
            self.forms.append(self._cur_form)
            self._cur_form = None


def parse_forms(url: str, html: str) -> dict:
    """v1.0 스펙 페이지 dict 반환."""
    p = _FormExtractor(url)
    try:
        p.feed(html)
    except Exception:
        pass
    return {"url": url, "forms": p.forms}
