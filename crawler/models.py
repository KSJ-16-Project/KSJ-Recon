from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

from crawler.auth.models import AuthConfig, AuthResult


@dataclass
class FormField:
    name: str = ""
    field_type: str = "text"
    id: str = ""
    placeholder: str = ""
    aria_label: str = ""
    value: str = ""
    required: bool = False

    @property
    def type(self) -> str:
        return self.field_type


@dataclass
class FormInfo:
    action: str = ""
    method: str = "GET"
    enctype: str = ""
    fields: list[FormField] = field(default_factory=list)


@dataclass
class CrawlerConfig:
    target_url: str
    headers: dict = field(default_factory=dict)
    max_depth: int = 2
    max_pages: int = 30
    concurrency: int = 4
    timeout: int = 30
    render_wait: int = 1000
    scan_budget: int = 600
    path_depth_limit: int = 12
    query_variants_limit: int = 3
    block_heavy_resources: bool = True
    enable_dynamic_discovery: bool = True
    auth: AuthConfig | None = None


@dataclass
class EndpointHint:
    url: str
    method: str = "GET"
    source: str = ""
    page_url: str = ""


@dataclass
class PageSnapshot:
    url: str
    depth: int = 0
    status: int = 0
    raw_html: str = ""
    rendered_html: str = ""
    links: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    routes: list[str] = field(default_factory=list)
    forms: list[FormInfo] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    render_type: str = ""
    xhr_list: list = field(default_factory=list)
    ws_list: list = field(default_factory=list)
    endpoint_hints: list[EndpointHint] = field(default_factory=list)
    request_headers: dict = field(default_factory=dict)
    response_headers: dict = field(default_factory=dict)
    cookies: list = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    url_params: dict = field(default_factory=dict)


@dataclass
class CrawlResult:
    target_url: str
    public_pages: list[PageSnapshot] = field(default_factory=list)
    authenticated_pages: list[PageSnapshot] = field(default_factory=list)
    auth: AuthResult | None = None
    sitemap_urls: list[str] = field(default_factory=list)
    robots_info: dict = field(default_factory=dict)
    endpoint_hints: list[EndpointHint] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def pages(self) -> list[PageSnapshot]:
        return self.public_pages + self.authenticated_pages

    def _target_netloc(self) -> str:
        return urlparse(self.target_url).netloc

    def scoped_links(self) -> list[str]:
        """target_url 도메인 내 링크만 중복 없이 반환. core/공격 모듈 전달용."""
        netloc = self._target_netloc()
        seen: set[str] = set()
        result: list[str] = []
        for page in self.pages:
            for link in page.links:
                if urlparse(link).netloc == netloc and link not in seen:
                    seen.add(link)
                    result.append(link)
        return result

    def scoped_endpoint_hints(self) -> list[EndpointHint]:
        """target_url 도메인 내 endpoint_hints만 반환. core/공격 모듈 전달용."""
        netloc = self._target_netloc()
        return [h for h in self.endpoint_hints if urlparse(h.url).netloc == netloc]
