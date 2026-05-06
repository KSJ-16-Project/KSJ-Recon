# ksj_login 모듈 가이드

크롤링이나 공격 진행 중 **세션이 만료됐을 때 자동으로 세션을 갱신(재로그인)** 하기 위한 모듈.
`crawler/auth/`의 기능을 개선하고, crawler 전용이 아닌 **프로젝트 전체에서 공유하는 인증 라이브러리**로 분리한 것이다.

- Python 3.10+ / 핵심 의존성: `playwright` (async API)
- **담당 범위**: `ksj_login/` 모듈만. `entry_core.py` 연결, SQLi/XSS 모듈 연동은 각 담당자 몫.

---

## 1. 탄생 배경 및 향후 계획

`crawler/auth/`는 crawler 내부 전용으로 설계됐지만, 공격 모듈(SQLi, XSS 등)도 로그인·세션 갱신 기능이 필요해 `ksj_login/`으로 독립 모듈화·개선했다.

- **현재**: `crawler/auth/`와 `ksj_login/`이 동일 기능을 병존 중
- **향후**: `crawler/auth/` 삭제 후 import 경로만 `crawler.auth.*` → `ksj_login.*`으로 변경

---

## 2. 전체 파이프라인에서의 위치

```
entry_core.py (core 팀)
  ├─ ksj_login.store_credentials(login_url, id, pw)
  ├─ asyncio.run(ksj_login.get_session())  ← 로그인 검증 + 재입력 루프
  └─ crawl_target(CrawlerConfig(...))
        └─ crawler engine
              ├─ public 크롤
              ├─ ksj_login.has_credentials() → True
              ├─ ksj_login.get_session() → AuthResult (2차 크롤용 쿠키)
              └─ authenticated 크롤
                    └─→ AuthResult (cookies 포함)
                          │
                          ├─→ SQLi 모듈 (다른 담당자)
                          │     auth = {"cookie": to_cookie_header(auth_result.cookies)}
                          │     # 세션 만료 시 → relogin(browser, auth_result)
                          │
                          └─→ XSS 모듈 (다른 담당자)
                                cookies = to_cookie_dict(auth_result.cookies)
                                # 세션 만료 시 → relogin(browser, auth_result)
```

**세션 만료 감지는 각 공격 모듈이 담당**하고, 감지 후 `relogin()`으로 쿠키를 갱신한다.

---

## 3. 디렉터리 구조

```
ksj_login/
├── __init__.py       # 공개 API export
├── models.py         # AuthConfig, AuthResult, FormSelectors
├── detector.py       # 로그인 폼 식별 휴리스틱
├── form_analyzer.py  # 폼 → Playwright 셀렉터 추론
├── login.py          ★ 실제 로그인 수행 (Playwright)
├── relogin.py        ★ 세션 갱신 (재로그인, 실패 시 최대 3회 재시도)
├── layer.py          # detector → form_analyzer → login 순서 호출 / <form> 밖 input은 Playwright 폴백 탐지
└── converter.py      # 쿠키 포맷 변환 (to_cookie_header, to_cookie_dict)
```

---

## 4. 공개 API (`__init__.py`)

```python
from ksj_login import (
    AuthConfig,          # 로그인 설정 (username, password, success_url_pattern)
    AuthResult,          # 로그인 결과 (cookies, local_storage, session_storage 등)
    FormSelectors,       # Playwright 셀렉터
    run_login,           # 최초 로그인 (crawler layer.py가 호출)
    relogin,             # 세션 만료 후 갱신 (공격 모듈이 호출)
    to_cookie_header,    # cookies → "name=value; ..." 문자열 (SQLi용)
    to_cookie_dict,      # cookies → {"name": "value"} dict (XSS용)
    store_credentials,   # core가 login_url/id/pw 저장 (crawl_target 호출 전)
    has_credentials,     # crawler engine이 인증 크롤 필요 여부 판단 시 호출
    get_session,         # 저장된 자격증명으로 로그인 수행 → AuthResult 반환
)
```

---

## 5. 공격 모듈에서의 사용 패턴

### SQLi
```python
from ksj_login import to_cookie_header, relogin

# 크롤러한테 auth_result 받아서 쿠키 변환 후 스캔
auth = {"cookie": to_cookie_header(auth_result.cookies)}
result = await run_scan(ScanInput(..., auth=auth))

# 스캔 중 세션 만료 감지 시
if result.auth_expired:
    auth_result = await relogin(browser, auth_result)
    auth = {"cookie": to_cookie_header(auth_result.cookies)}
    # 스캔 재시도
```

### XSS
```python
from ksj_login import to_cookie_dict, relogin

# 쿠키 dict로 변환 후 스캔
cookies = to_cookie_dict(auth_result.cookies)

# 세션 만료 시
auth_result = await relogin(browser, auth_result)
cookies = to_cookie_dict(auth_result.cookies)
```

---

## 6. 이해 순서

```
models.py        ← 1순위. 입출력 구조 정의
    AuthConfig   : 사용자가 제공하는 아이디/비밀번호 설정
    FormSelectors: form_analyzer가 추론한 Playwright 셀렉터 (login의 입력)
    AuthResult   : login의 출력. cookies가 공격 모듈에 주입됨

detector.py      ← 2순위. 어떤 URL과 폼 정보가 넘어오는지
form_analyzer.py ← 3순위. 어떤 셀렉터가 넘어오는지
layer.py         ← 4순위. login이 어떤 순서로 호출되는지
login.py         ← 5순위. 실제 로그인 구현
relogin.py       ← 6순위. 세션 갱신 구현
converter.py     ← 7순위. 쿠키 포맷 변환
```

### 설계 의도 (코드에 안 나오는 것들)

**`layer.py` — `_detect_form_with_playwright` 폴백이 있는 이유**
크롤러가 넘겨주는 페이지 데이터는 `<form>` 태그 안의 필드만 파싱한다. password input이 `<form>` 밖에 있으면 `detector.py`의 `find_login_page()`가 None을 반환한다. 이때 `_detect_form_with_playwright()`가 Playwright로 직접 URL을 방문해 DOM 전체에서 `input[type=password]`를 탐색하고 FormSelectors를 생성한다. `<form>` 태그 여부와 무관하게 동작하므로 크롤러 데이터 형식 변경 없이 처리된다.

**`login.py` — `_is_login_success`에서 URL 확인을 에러 키워드보다 먼저 하는 이유**
로그인 성공 후 메인 페이지로 리다이렉트되면 해당 페이지의 정상 텍스트(예: "강좌가 없습니다")가 에러 키워드와 겹쳐 false positive를 일으킨다. URL이 이미 비로그인 페이지로 바뀐 시점은 성공이 확정된 것이므로 에러 키워드 검사 자체가 불필요하다. 에러 키워드 검사는 URL이 바뀌지 않아 아직 로그인 페이지에 머물러 있는 경우에만 의미 있다.

**`detector.py` — method 검사 안 하는 이유**
React/Vue SPA는 폼에 method 속성을 안 붙이고 onSubmit 핸들러로 처리하므로 method='get'(기본값)으로 보일 수 있다. password 필드 유무로 충분히 구분된다.

**`detector.py` — `_NON_SUBMITTABLE_TYPES`에서 `submit` 제외 이유**
로그인/회원가입 구분은 "사용자가 값을 입력하는 필드 수"로 판단한다. `type=submit`은 버튼이지 입력 필드가 아니므로 카운트에서 빼야 정확하다.

**`form_analyzer.py` — placeholder가 셀렉터 3순위인 이유**
`name` → `id` → `placeholder` 순으로 셀렉터를 생성한다. placeholder는 name도 id도 없는 input을 찾기 위한 마지막 수단이다.

**`AuthResult`에 `selectors`와 `config`를 저장하는 이유**
`relogin()`이 이전 로그인 결과만 받아서 재로그인할 수 있도록 하기 위해서다. 호출자가 셀렉터나 설정을 별도로 보관할 필요가 없다.

**`converter.py`를 별도 파일로 분리한 이유**
공격 모듈마다 쿠키 포맷이 다르다 (SQLi는 헤더 문자열, XSS는 dict). 변환 로직을 한 곳에 모아 중복을 방지한다.

**`login.py` — `_submit_login_form()`에 `javascript:` href fallback이 있는 이유**
`<a href="javascript:chkForm();">` 형태의 로그인 버튼은 onclick 속성도 없고 button/input[type=submit]도 아니어서 기존 셀렉터에 안 걸린다. 이 경우 DOM 순서상 password input 이후에 등장하는 첫 번째 `javascript:` href 링크 또는 `input[type=image]`를 submit 버튼으로 사용한다.

---

## 7. 완료된 수정 사항

| 파일 | 내용 |
|---|---|
| `relogin.py` | 실패 시 최대 3회 재시도 + 2초 딜레이 추가 (`max_retries=3`, `retry_delay=2.0`) |
| `login.py` | 네비게이션 대기 전략 개선 — `wait_for_url` 우선, `networkidle` 폴백 |
| `login.py` | submit 버튼 탐색 범위 확장 — 폼 내부 우선, 없으면 부모 컨테이너까지 탐색 |
| `login.py` | `[debug]` print 3곳 제거 |
| `login.py` | dialog 핸들러 추가 — 폼 제출 전 `page.on("dialog", ...)` 등록, alert/confirm 자동 수락 후 리다이렉트 진행 |
| `login.py` | `_is_login_success` 로직 개선 — URL 변경 확인을 에러 키워드 검사보다 먼저 수행. 리다이렉트 후 메인 페이지의 정상 텍스트("강좌가 없습니다" 등)가 에러 키워드로 오탐되던 문제 수정. `page.content()`(전체 HTML) → `document.body.innerText`(보이는 텍스트만)로 변경 |
| `models.py` | 미구현 상태였던 `login_requests` 필드 제거 |
| `layer.py` | `<form>` 밖 input 처리 — `find_login_page()` 실패 시 `_detect_form_with_playwright()` 폴백 추가. Playwright로 직접 URL 방문 후 DOM에서 password input 탐색, DOM 순서 기준으로 username 추론 |
| `layer.py` | `FormSelectors` import 누락 수정 — `_detect_form_with_playwright()` 내부 NameError가 `except Exception: pass`에 조용히 잡혀 항상 `(None, None)` 반환하던 버그 수정 |
| `credentials.py` | 신규 추가 — `store_credentials`, `has_credentials`, `get_session` 구현. `get_session()`은 `async_playwright()`로 브라우저를 내부에서 직접 생성하므로 호출자가 브라우저 객체 불필요 |
| `__init__.py` | `store_credentials`, `has_credentials`, `get_session` export 추가 |
| `login.py` | `_submit_login_form()` — `javascript:` href 버튼 fallback 추가. `<a href="javascript:chkForm();">` 형태의 버튼을 password input 이후 DOM 순서 기준으로 탐지 |

---

## 8. 알려진 이슈 / 주의점

### AuthResult 모델 불일치 (구조적 문제)
`ksj_login/models.py`의 `AuthResult`에는 `config: Optional[AuthConfig]` 필드가 있지만 `crawler/auth/models.py`에는 없다. `crawler/auth/` 삭제 전까지 두 모델이 따로 존재한다.

### get_session() 브라우저 이중 실행
core 재입력 루프에서 `get_session()` 호출 시 브라우저를 켰다 닫고, crawler 2차 크롤 전에 또 `get_session()` 호출 시 브라우저를 다시 켰다 닫는다. 로그인을 두 번 수행하는 구조. 기능 문제는 없으나 각 호출마다 Chromium 실행 오버헤드(약 2~3초)가 발생한다.

---

## 9. credentials.py — 완료

`credentials.py`가 구현 완료됐다. `__init__.py` export도 추가됨.

### 핵심 설계: `get_session()`은 브라우저 파라미터 없음 (Method B)

```python
async def get_session() -> AuthResult:
    """브라우저를 내부에서 생성하므로 호출자는 browser 객체 불필요."""
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        try:
            # ... 로그인 수행 ...
        finally:
            await browser.close()
```

**왜 브라우저를 내부에서 생성하나?**
- core는 브라우저 객체가 없어서 `get_session(browser)`를 호출할 수 없다
- core의 재입력 루프(`store_credentials → get_session → 실패 시 재입력`)를 구현하려면 core가 직접 `get_session()`을 호출해야 한다
- `async_playwright()`를 직접 써서 독립적으로 브라우저를 생성·소멸하므로 crawler에 의존하지 않는다

### 호출 흐름 (완성된 설계)

```
core
 ├─ login_url, id, pw 입력받기
 ├─ ksj_login.store_credentials(login_url, id, pw)
 ├─ auth_result = await ksj_login.get_session()  ← 로그인 검증
 │    ├─ 성공: crawl_target() 호출로 진행
 │    └─ 실패: 재입력 요청 → store_credentials() → get_session() 재시도
 └─ crawl_target(CrawlerConfig(...))
      └─ crawler engine (public 크롤 완료 후)
           ├─ ksj_login.has_credentials()  → True
           └─ ksj_login.get_session()      → AuthResult (2차 크롤용 쿠키)
```

### 각 팀 변경 필요 사항

**core 팀** — `entry_core.py`에 추가:
```python
import ksj_login
import asyncio

# login 선택 시:
login_url = input("로그인 URL: ")
ksj_login.store_credentials(login_url, user_id, user_password)

# 재입력 루프:
while True:
    auth_result = asyncio.run(ksj_login.get_session())
    if auth_result.success:
        break
    print(f"로그인 실패: {auth_result.error}")
    login_url     = input("로그인 URL: ")
    user_id       = input("아이디: ")
    user_password = input("비밀번호: ")
    ksj_login.store_credentials(login_url, user_id, user_password)
```

**crawler 팀** — `engine.py:65` 수정:
```python
# 변경 전
auth_result = await ksj_login.get_session(browser)

# 변경 후
auth_result = await ksj_login.get_session()
```

---

## 10. 의존성 그래프

```
core/entry_core
  └─→ ksj_login/credentials (store_credentials, get_session)  ← 재입력 루프

crawler/engine
  ├─→ ksj_login/layer (run_login)        ← 향후 crawler/auth/ 교체 대상
  │     └─→ AuthResult
  └─→ ksj_login/credentials (has_credentials, get_session)
        └─→ AuthResult

공격 모듈 (SQLi, XSS — 다른 담당자)
  └─→ ksj_login (relogin, to_cookie_header, to_cookie_dict)

ksj_login/layer       ─→ detector, form_analyzer, login, models
ksj_login/relogin     ─→ login, models
ksj_login/credentials ─→ form_analyzer, login, models, async_playwright
ksj_login/converter   ─→ (표준 라이브러리만)
```

순환 의존 없음.
