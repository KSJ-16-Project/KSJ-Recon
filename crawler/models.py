from __future__ import annotations

from dataclasses import dataclass, field

from crawler.auth.models import AuthConfig, AuthResult
from crawler.parser import FormInfo


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
