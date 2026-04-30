"""
parser.py — HTML 파싱 & 정보 추출 모듈

네트워크 호출 없는 순수 함수 모음. 렌더링된 HTML 문자열을 입력받아 처리한다.
piscovery 참고: piscovery/spider/parse.py
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import parse_qs, urljoin, urlparse


# ── 임시 데이터 모델 ──────────────────────────────────────────
# core/models.py 확정 후 아래 두 클래스를 삭제하고
# from core.models import FormField, FormInfo 로 교체한다.

@dataclass
class FormField:
    name: str
    field_type: str = "text"
    required: bool = False

@dataclass
class FormInfo:
    action: str = ""
    method: str = "GET"
    fields: list[FormField] = field(default_factory=list)


# ── 내부용 HTML 파서 ──────────────────────────────────────────
# [학습 포인트] HTMLParser 상속
#   HTML을 위에서 아래로 읽으면서 태그를 만날 때마다
#   handle_starttag / handle_endtag 가 자동 호출된다.

class _PageParser(HTMLParser):

    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.title: str = ""
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[FormInfo] = []
        self.manifest_url: str = ""
        self._current_form: Optional[FormInfo] = None
        self._in_title: bool = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        # attrs 예시: <a href="/login" class="btn"> → [("href", "/login"), ("class", "btn")]
        attr = dict(attrs)

        if tag in ("a", "area"):
            href = attr.get("href") or ""
            if href and not href.startswith(("#", "mailto:", "javascript:")):
                # [학습 포인트] urljoin: 상대 경로 → 절대 URL 변환
                self.links.append(urljoin(self.base_url, href))

        elif tag == "script":
            src = attr.get("src") or ""
            if src:
                self.scripts.append(urljoin(self.base_url, src))

        elif tag == "link":
            rel = attr.get("rel") or ""
            href = attr.get("href") or ""
            if rel == "manifest" and href:
                self.manifest_url = urljoin(self.base_url, href)

        elif tag == "title":
            self._in_title = True

        elif tag == "form":
            self._current_form = FormInfo(
                action=urljoin(self.base_url, attr.get("action") or ""),
                method=(attr.get("method") or "GET").upper(),
            )

        elif self._current_form is not None:
            name = attr.get("name") or ""
            if not name:
                return
            if tag == "input":
                self._current_form.fields.append(FormField(
                    name=name,
                    field_type=attr.get("type") or "text",
                    required="required" in attr,
                ))
            elif tag in ("textarea", "select"):
                self._current_form.fields.append(FormField(
                    name=name,
                    field_type=tag,
                    required="required" in attr,
                ))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data.strip()


# ── CSR 프레임워크 탐지 패턴 ──────────────────────────────────
_CSR_PATTERNS: dict[str, str] = {
    "React":   r"data-reactroot|_reactFiber|__REACT_DEVTOOLS_GLOBAL_HOOK__",
    "Vue":     r"__vue__|data-v-[a-f0-9]{7,8}",
    "Angular": r"ng-version=|ng-app=|ng-controller=",
    "Svelte":  r"__svelte|svelte-[a-z0-9]+",
}

def detect_csr_framework(html: str) -> Optional[str]:
    """React / Vue / Angular / Svelte 중 사용 프레임워크를 반환한다. 탐지 실패 시 None."""
    for name, pattern in _CSR_PATTERNS.items():
        if re.search(pattern, html, re.IGNORECASE):
            return name
    return None


# ── 기술스택 탐지 패턴 ────────────────────────────────────────
_TECH_FINGERPRINTS: list[tuple[str, str, str]] = [
    ("WordPress",  "html",                 r"wp-content|wp-includes"),
    ("React",      "html",                 r"data-reactroot|_reactFiber"),
    ("Vue.js",     "html",                 r"__vue__|data-v-[a-f0-9]"),
    ("Angular",    "html",                 r"ng-version=|ng-app="),
    ("Next.js",    "html",                 r"__NEXT_DATA__|/_next/static"),
    ("Nuxt.js",    "html",                 r"__NUXT__|/_nuxt/"),
    ("jQuery",     "html",                 r"jquery[.\-][\d]+"),
    ("Bootstrap",  "html",                 r"bootstrap\.min\.css|bootstrap\.bundle"),
    ("Nginx",      "header:server",        r"nginx"),
    ("Apache",     "header:server",        r"apache"),
    ("PHP",        "header:x-powered-by",  r"php"),
    ("ASP.NET",    "header:x-powered-by",  r"asp\.net"),
    ("Express",    "header:x-powered-by",  r"express"),
]

_JS_ENDPOINT_PATTERNS: list[str] = [
    r"""fetch\s*\(\s*["']([^"']+)["']""",
    r"""axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']""",
    r"""\$\s*\.\s*(?:get|post|ajax)\s*\(\s*["']([^"']+)["']""",
    r"""\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["']([^"']+)["']""",
]

# SPA 클라이언트 라우트 패턴 (React Router, Vue Router 등)
_ROUTE_PATTERNS: list[str] = [
    r"""path\s*:\s*["']([^"']+)["']""",
    r"""route\s*\(\s*["']([^"']+)["']""",
    r"""<Route\s+[^>]*path=["']([^"']+)["']""",
]


# ── 공개 함수 ─────────────────────────────────────────────────

def is_html(content_type: str) -> bool:
    """응답이 HTML인지 확인한다. 크롤링 대상 여부 판단에 사용."""
    return "text/html" in content_type.lower()


def extract_links(html: str, base_url: str) -> list[str]:
    """HTML에서 링크를 추출해 절대 URL 목록으로 반환한다. (중복 제거)"""
    parser = _PageParser(base_url)
    parser.feed(html)
    seen: set[str] = set()
    result: list[str] = []
    for url in parser.links:
        if url not in seen:
            seen.add(url)
            result.append(url)
    return result


def extract_forms(html: str) -> list[FormInfo]:
    """HTML에서 폼과 입력 필드 목록을 추출한다."""
    parser = _PageParser("")
    parser.feed(html)
    return parser.forms


def extract_scripts(html: str) -> list[str]:
    """HTML에서 외부 JS 파일 URL 목록을 추출한다."""
    parser = _PageParser("")
    parser.feed(html)
    return parser.scripts


def extract_endpoints(js_text: str) -> list[str]:
    """JS 코드에서 fetch / axios / $.ajax / XHR 패턴으로 API URL을 추출한다."""
    found: set[str] = set()
    for pattern in _JS_ENDPOINT_PATTERNS:
        for match in re.finditer(pattern, js_text):
            url = match.group(1)
            if len(url) > 1 and not url.startswith("data:"):
                found.add(url)
    return list(found)


def extract_routes_from_js(js_text: str) -> list[str]:
    """SPA JS 번들에서 클라이언트 사이드 라우트 경로를 추출한다."""
    found: set[str] = set()
    for pattern in _ROUTE_PATTERNS:
        for match in re.finditer(pattern, js_text):
            path = match.group(1)
            if path.startswith("/") and len(path) > 1:
                found.add(path)
    return list(found)


def detect_technologies(html: str, headers: dict[str, str]) -> list[str]:
    """HTML 본문과 HTTP 응답 헤더에서 사용 기술스택을 탐지한다."""
    detected: list[str] = []
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

    for tech_name, target, pattern in _TECH_FINGERPRINTS:
        if target == "html":
            if re.search(pattern, html, re.IGNORECASE):
                detected.append(tech_name)
        elif target.startswith("header:"):
            header_key = target.split(":", 1)[1]
            if re.search(pattern, headers_lower.get(header_key, ""), re.IGNORECASE):
                detected.append(tech_name)

    return detected


def detect_render_type(raw_html: str, rendered_html: str) -> str:
    """
    렌더링 전(raw)과 후(rendered) HTML을 비교해 SSR / CSR / Static 을 반환한다.

    [학습 포인트]
      raw_html:      서버에서 받은 원본 HTML (JS 실행 전, sitemap.py 의 fetch_url 결과)
      rendered_html: Playwright 가 JS 실행 후 가져온 HTML (renderer.py 의 page.content() 결과)
    """
    raw_len = len(raw_html.strip())
    rendered_len = len(rendered_html.strip())

    if rendered_len < 500:
        return "Static"

    # rendered 가 raw 보다 30% 이상 길면 JS 가 DOM 을 많이 생성한 것 → CSR
    if raw_len > 0 and (rendered_len - raw_len) / raw_len > 0.3:
        return "CSR"

    return "SSR"


def parse_cookies(cookie_header: str) -> dict[str, str]:
    """
    Set-Cookie 헤더 문자열을 {이름: 값} 딕셔너리로 파싱한다.

    예) "session=abc123; Path=/; HttpOnly" → {"session": "abc123"}
    """
    cookies: dict[str, str] = {}
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, val = part.partition("=")
            key = key.strip()
            # Path, Domain, HttpOnly, Secure, SameSite 메타 속성은 제외
            if key.lower() not in ("path", "domain", "expires", "max-age",
                                   "samesite", "httponly", "secure"):
                cookies[key] = val.strip()
    return cookies


# [LLM 필터링 대상] 파라미터 이름·값의 보안 민감도 판단 (SQLi/XSS 공격 가능성)
def extract_url_params(url: str) -> dict[str, list[str]]:
    """
    URL 쿼리 파라미터를 {파라미터명: [값, ...]} 딕셔너리로 반환한다.

    예) "https://example.com/search?q=hello&page=2"
        → {"q": ["hello"], "page": ["2"]}
    """
    query = urlparse(url).query
    return parse_qs(query)


# [LLM 필터링 대상] 민감 정보 노출 여부 판단 (내부 경로, 자격증명, TODO 등)
def extract_comments(html: str) -> list[str]:
    """HTML 주석(<!-- ... -->) 을 추출해 목록으로 반환한다."""
    comments = re.findall(r"<!--(.*?)-->", html, re.DOTALL)
    return [c.strip() for c in comments if c.strip()]
