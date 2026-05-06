# crawler

Playwright 기반 웹 크롤러 모듈. 대상 URL을 정적·동적으로 크롤링하여 페이지 구조, API 엔드포인트, 인증 흐름 등을 수집하고 공격 모듈이 사용할 수 있는 형태로 반환한다.

---

## 모듈 구조

```
crawler/
├── engine.py          # 크롤링 오케스트레이터 (crawl_target 진입점)
├── models.py          # 입출력 데이터 모델 (CrawlerConfig, CrawlResult 등)
├── parser.py          # HTML/JS 파싱 순수 함수 모음
├── discovery.py       # SPA 동적 URL 탐색 (click_walk, history_urls)
├── sitemap.py         # robots.txt / sitemap.xml 수집
├── browser/
│   ├── browser.py     # BrowserManager, RawPageData, XHRRecord, WSRecord
│   └── render.py      # 페이지 렌더링, XHR/WS 수집, 동적 탐색 실행
└── auth/
    ├── layer.py        # 인증 오케스트레이터
    ├── login.py        # 로그인 실행
    ├── detector.py     # 로그인 페이지 탐지
    ├── form_analyzer.py# 로그인 폼 분석
    └── models.py       # AuthConfig, AuthResult
```

---

## core → crawler: 입력

`crawl_target(config: CrawlerConfig)` 을 호출하여 크롤링을 시작한다.

### `CrawlerConfig`

| 필드 | 타입 | 기본값 | 설명 |
|------|------|--------|------|
| `target_url` | `str` | (필수) | 크롤링 시작 URL |
| `headers` | `dict` | `{}` | 모든 요청에 추가할 HTTP 헤더 |
| `max_depth` | `int` | `2` | 크롤링 최대 깊이 |
| `max_pages` | `int` | `30` | 수집할 최대 페이지 수 |
| `concurrency` | `int` | `4` | 동시 렌더링 수 (최대 4) |
| `timeout` | `int` | `30` | 페이지당 렌더링 타임아웃 (초) |
| `render_wait` | `int` | `1000` | 렌더링 후 JS 실행 대기 시간 (ms) |
| `scan_budget` | `int` | `600` | 전체 크롤링 시간 제한 (초) |
| `path_depth_limit` | `int` | `12` | URL 경로 깊이 제한 |
| `query_variants_limit` | `int` | `3` | 동일 경로의 쿼리 파라미터 변형 허용 수 |
| `block_heavy_resources` | `bool` | `True` | 이미지/폰트/미디어 요청 차단 여부 |
| `auth` | `AuthConfig \| None` | `None` | 로그인 설정 (미입력 시 비인증 크롤만 수행) |

### `AuthConfig` (선택)

| 필드 | 타입 | 기본값 | 설명 |
|------|------|--------|------|
| `username` | `str` | `""` | 로그인 계정 |
| `password` | `str` | `""` | 로그인 비밀번호 |
| `success_url_pattern` | `str` | `""` | 로그인 성공 판단용 URL 패턴 (정규식) |
| `enabled` | `bool` | `True` | 인증 레이어 활성화 여부 |

### 사용 예시

```python
from crawler.engine import crawl_target
from crawler.models import CrawlerConfig
from crawler.auth.models import AuthConfig

config = CrawlerConfig(
    target_url="https://example.com",
    max_depth=3,
    max_pages=50,
    auth=AuthConfig(username="admin", password="password"),
)

result = await crawl_target(config)
```

---

## crawler → core: 출력

`crawl_target()` 은 `CrawlResult` 를 반환한다.

### `CrawlResult`

| 필드 | 타입 | 설명 |
|------|------|------|
| `target_url` | `str` | 크롤링 대상 URL |
| `public_pages` | `list[PageSnapshot]` | 비인증 상태에서 수집한 페이지 |
| `authenticated_pages` | `list[PageSnapshot]` | 로그인 후에만 접근 가능한 페이지 |
| `auth` | `AuthResult \| None` | 인증 수행 결과 (`auth` 미설정 시 `None`) |
| `sitemap_urls` | `list[str]` | sitemap.xml에서 수집한 URL 목록 |
| `robots_info` | `dict` | `{"disallowed": [...], "sitemaps": [...]}` |
| `endpoint_hints` | `list[EndpointHint]` | 전체 페이지에서 중복 제거된 API 엔드포인트 후보 |
| `errors` | `list[str]` | 크롤링 중 발생한 오류 메시지 |
| `pages` | `list[PageSnapshot]` | `public_pages + authenticated_pages` (property) |

---

### `PageSnapshot` — 페이지별 수집 데이터

| 필드 | 타입 | 설명 |
|------|------|------|
| `url` | `str` | 페이지 URL |
| `depth` | `int` | 크롤링 깊이 |
| `status` | `int` | HTTP 응답 코드 |
| `raw_html` | `str` | 서버 원본 HTML (JS 실행 전) |
| `rendered_html` | `str` | 렌더링된 HTML (JS 실행 후) |
| `links` | `list[str]` | 동일 도메인 링크 (in-scope only) |
| `scripts` | `list[str]` | 동일 도메인 JS 파일 URL (in-scope only) |
| `routes` | `list[str]` | SPA 클라이언트 사이드 라우트 (in-scope only) |
| `forms` | `list[FormInfo]` | 폼 정보 (action, method, fields) |
| `technologies` | `list[str]` | 탐지된 기술 스택 (React, Nginx, PHP 등) |
| `render_type` | `str` | `"CSR"` / `"SSR"` / `"Static"` |
| `csr_framework` | `str` | `"React"` / `"Vue"` / `"Angular"` / `"Svelte"` / `""` |
| `xhr_list` | `list[XHRRecord]` | XHR/Fetch 요청 전체 (외부 도메인 포함) |
| `ws_list` | `list[WSRecord]` | WebSocket 연결 전체 (외부 도메인 포함) |
| `endpoint_hints` | `list[EndpointHint]` | XHR·WS·JS 정적 분석으로 추출한 API 후보 (**외부 도메인 포함** — SSRF 모듈 활용) |
| `request_headers` | `dict` | 실제 전송된 요청 헤더 |
| `response_headers` | `dict` | 수신한 응답 헤더 |
| `cookies` | `list` | 수집된 쿠키 |
| `comments` | `list[str]` | HTML 주석 (`<!-- -->`) — 민감 정보 노출 탐지용 |
| `url_params` | `dict[str, list[str]]` | URL 쿼리 파라미터 `{"key": ["value", ...]}` — SQLi/XSS 공격 파라미터 식별용 |

---

### `EndpointHint` — API 엔드포인트 후보

| 필드 | 타입 | 설명 |
|------|------|------|
| `url` | `str` | 엔드포인트 URL |
| `method` | `str` | HTTP 메서드 (`GET`, `POST`, `WS` 등) |
| `source` | `str` | 수집 출처 (`xhr`, `fetch`, `websocket`, `js-static`) |
| `page_url` | `str` | 이 힌트가 발견된 페이지 URL |

---

### `AuthResult`

| 필드 | 타입 | 설명 |
|------|------|------|
| `success` | `bool` | 로그인 성공 여부 |
| `attempted` | `bool` | 로그인 시도 여부 |
| `login_url` | `str` | 로그인 폼이 발견된 URL |
| `final_url` | `str` | 로그인 후 최종 도달 URL |
| `cookies` | `list[dict]` | 인증 세션 쿠키 |
| `local_storage` | `dict` | localStorage 값 |
| `session_storage` | `dict` | sessionStorage 값 |
| `reason` | `str` | 성공/실패 이유 |
| `login_requests` | `list` | 로그인 과정에서 발생한 POST 요청 전체 |

---

## 크롤링 흐름

```
crawl_target(config)
  └─ _crawl_with_browser()
       ├─ _crawl_once()  [phase: public]
       │    ├─ robots.txt / sitemap.xml 수집
       │    └─ BFS 루프
       │         ├─ render()          ← Playwright 렌더링 + XHR/WS 수집
       │         │    └─ click_walk() ← SPA 버튼 클릭으로 동적 URL 수집 (상시)
       │         ├─ _snapshot_from_raw()   ← RawPageData → PageSnapshot 변환
       │         └─ _enrich_from_scripts() ← JS 파일 정적 분석
       └─ _crawl_once()  [phase: authenticated]  ← auth.success 시에만
            └─ (동일 흐름, 로그인 세션 적용)
```

### 스코프 정책

| 데이터 | 정책 | 이유 |
|--------|------|------|
| `links`, `scripts`, `routes` | **in-scope only** (동일 도메인) | 크롤 큐에 들어가므로 외부 사이트 크롤 방지 |
| `endpoint_hints` (XHR/WS/JS) | **외부 도메인 포함** | SSRF 모듈이 외부로 향하는 요청을 타깃으로 활용 |

---

## CLI 직접 실행

```bash
python -m crawler --url https://example.com [옵션]

옵션:
  --url               크롤링 대상 URL (기본: http://localhost/)
  --username          로그인 계정
  --password          로그인 비밀번호
  --max-depth INT     크롤링 깊이 (기본: 2)
  --max-pages INT     최대 페이지 수 (기본: 20)
  --concurrency INT   동시 렌더링 수 (기본: 3)
  --render-wait INT   렌더링 대기 시간 ms (기본: 1000)
  --headless          브라우저 창 없이 실행
  --format {text,json} 출력 형식 (기본: json)
```
