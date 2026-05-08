"""Normalize core input JSON into scanner targets."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from urllib.parse import urlparse, parse_qs, urldefrag


@dataclass
class Target:
    url: str
    method: str = "GET"
    params: dict | None = None
    attack_params: list[str] | None = None
    headers: dict | None = None
    cookies: dict | None = None
    type: str = "page"
    safe_to_submit: bool = False
    check_urls: list[str] | None = None
    source: str = "input"
    body_format: str = "form"
    source_url: str | None = None
    view_url: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class TargetExtractor:
    def __init__(self, input_data: dict):
        self.input_data = input_data.get("xss_data", input_data)

    def extract(self) -> list[dict]:
        targets: list[Target] = []

        for item in self.input_data.get("urls", []):
            if isinstance(item, str):
                targets.append(self._from_url_string(item, source="urls"))
            elif isinstance(item, dict) and (item.get("url") or item.get("submit_url")):
                targets.append(self._from_item(item, source="urls"))

        for key in ("spider_urls", "fuzzer_urls"):
            for url in self.input_data.get(key, []):
                if isinstance(url, str):
                    targets.append(self._from_url_string(url, source=key))

        for item in self.input_data.get("stored_targets", []):
            if isinstance(item, dict) and (item.get("url") or item.get("submit_url")):
                targets.append(self._from_item(item, source="stored_targets"))

        # Deduplicate by method + defragmented URL + params + type + storage intent.
        # safe_to_submit/source/check_urls affect stored-XSS behavior and must be
        # preserved to avoid collapsing a safe stored target into an unsafe one.
        seen = set()
        unique: list[dict] = []
        for t in targets:
            d = t.to_dict()
            norm_url, _frag = urldefrag(d["url"])
            key = (
                d["method"],
                norm_url,
                tuple(sorted((d.get("params") or {}).items())),
                d.get("type"),
                bool(d.get("safe_to_submit", False)),
                d.get("source"),
                tuple(sorted(d.get("check_urls") or [])),
            )
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
        url = item.get("url") or item.get("submit_url")
        method = item.get("method", "GET").upper()
        params = item.get("params")
        if params is None:
            params = item.get("body")
        if params is None:
            params = item.get("fields")
        if params is None and method == "GET":
            parsed = urlparse(url)
            params = {k: v[0] if v else "" for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
        safe = bool(item.get("safe_to_submit", False))
        view_url = item.get("view_url")
        check_urls = item.get("check_urls")
        if check_urls is None and view_url:
            check_urls = [view_url]
        return Target(
            url=url,
            method=method,
            params=params or {},
            attack_params=item.get("attack_params", []),
            headers=item.get("headers", {}),
            cookies=item.get("cookies", {}),
            type=item.get("type", "page"),
            safe_to_submit=safe,
            check_urls=check_urls or [],
            source=source,
            body_format=item.get("body_format", "form"),
            source_url=item.get("source_url"),
            view_url=view_url,
        )
