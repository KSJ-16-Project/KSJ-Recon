"""Normalize core input JSON into scanner targets."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from urllib.parse import urlparse, parse_qs, urldefrag

from .payloads import HIGH_VALUE_PARAM_NAMES, DANGEROUS_FORM_HINTS


@dataclass
class Target:
    url: str
    method: str = "GET"
    params: dict | None = None
    headers: dict | None = None
    cookies: dict | None = None
    type: str = "page"
    safe_to_submit: bool = False
    check_urls: list[str] | None = None
    source: str = "input"
    body_format: str = "form"

    def to_dict(self) -> dict:
        return asdict(self)


class TargetExtractor:
    def __init__(self, input_data: dict):
        self.input_data = input_data

    def extract(self) -> list[dict]:
        targets: list[Target] = []

        for item in self.input_data.get("urls", []):
            if isinstance(item, str):
                targets.append(self._from_url_string(item, source="urls"))
            elif isinstance(item, dict) and item.get("url"):
                targets.append(self._from_item(item, source="urls"))

        for key in ("spider_urls", "fuzzer_urls"):
            for url in self.input_data.get(key, []):
                if isinstance(url, str):
                    targets.append(self._from_url_string(url, source=key))

        # Deduplicate by method + defragmented URL + params + type.
        seen = set()
        unique: list[dict] = []
        for t in targets:
            d = t.to_dict()
            norm_url, _frag = urldefrag(d["url"])
            key = (d["method"], norm_url, tuple(sorted((d.get("params") or {}).items())), d.get("type"))
            if key in seen:
                continue
            seen.add(key)
            unique.append(d)
        return unique

    def _from_url_string(self, url: str, source: str) -> Target:
        parsed = urlparse(url)
        params = {k: v[0] if v else "" for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
        return Target(url=url, method="GET", params=params, source=source)

    def _from_item(self, item: dict, source: str) -> Target:
        url = item["url"]
        method = item.get("method", "GET").upper()
        params = item.get("params")
        if params is None and method == "GET":
            parsed = urlparse(url)
            params = {k: v[0] if v else "" for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
        safe = bool(item.get("safe_to_submit", False))
        if method == "POST" and not safe:
            safe = self._looks_safe_form(url, params or {})
        return Target(
            url=url,
            method=method,
            params=params or {},
            headers=item.get("headers", {}),
            cookies=item.get("cookies", {}),
            type=item.get("type", "page"),
            safe_to_submit=safe,
            check_urls=item.get("check_urls", []),
            source=source,
            body_format=item.get("body_format", "form"),
        )

    def _looks_safe_form(self, url: str, params: dict) -> bool:
        text = (url + " " + " ".join(params.keys())).lower()
        if any(hint in text for hint in DANGEROUS_FORM_HINTS):
            return False
        # Only auto-safe for text-like, user-content forms.
        return any(name.lower() in HIGH_VALUE_PARAM_NAMES for name in params.keys())
