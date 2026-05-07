# XSS Module

Recon 결과 URL을 입력받아 Reflected XSS, Stored XSS, DOM XSS를 탐지하고 Playwright로 alert 실행을 브라우저 검증하는 경량 스캐너입니다.

## 설치

```bash
pip install -r requirements.txt
python -m playwright install chromium
```

Python 3.10 이상 권장

## 실행

```bash
# input.json을 기본값으로 사용
python xss_cli.py

# 입력 파일 지정
python xss_cli.py my_targets.json

# 결과 경로 지정
python xss_cli.py input.json -o results/report.json
```

결과는 `results/xss_result_YYYYMMDD_HHMMSS.json`에 저장됩니다.  
스캔 중에는 phase 단위로 `results/xss_result_partial.json`이 저장되며, 정상적으로 최종 결과 저장이 완료되면 partial 파일은 삭제됩니다.

---

## 입력 파일 형식 (input.json)

### 필수 필드

| 필드 | 타입 | 설명 |
|------|------|------|
| `base_url` | string | 스캔 대상의 루트 URL. 없으면 `spider_urls` / `urls`의 첫 절대 URL에서 자동 추출 시도 |

### 부가 필드 — 타겟 URL

| 필드 | 타입 | 설명 |
|------|------|------|
| `urls` | list | 상세 설정이 가능한 타겟 목록. 문자열 또는 객체 형태 모두 허용 |
| `spider_urls` | list\<string\> | 크롤러에서 수집한 URL 목록 (GET only, 쿼리 파라미터 자동 파싱) |
| `fuzzer_urls` | list\<string\> | 퍼저에서 수집한 URL 목록 (GET only, 쿼리 파라미터 자동 파싱) |
| `stored_targets` | list\<object\> | HTTP Stored XSS 전용 타겟 목록. 실제 제출은 `safe_to_submit: true`일 때만 수행 |

> `urls`, `spider_urls`, `fuzzer_urls`를 모두 생략하면 탐지할 타겟이 없으므로 결과가 비어있습니다.

### 부가 필드 — 인증

| 필드 | 타입 | 설명 |
|------|------|------|
| `session_id` | string | 세션 쿠키 값. 지정 시 login.py를 거치지 않음 |
| `token` | string | Authorization Bearer 토큰. 지정 시 login.py를 거치지 않음 |
| `login_mock_path` | string | `login_mock.json` 경로 수동 지정. 기본값: `XSS/login_mock.json` |

인증 우선순위: `session_id` / `token` → `login_mock.json` → 인증 없이 진행

### 부가 필드 — 전역 HTTP

| 필드 | 타입 | 설명 |
|------|------|------|
| `headers` | dict | 모든 요청에 추가되는 HTTP 헤더 |
| `cookies` | dict | 모든 요청에 추가되는 쿠키 |

### 부가 필드 — 경로

| 필드 | 타입 | 기본값 | 설명 |
|------|------|--------|------|
| `results_dir` | string | `results/` | 결과 JSON 저장 경로 |

### 부가 필드 — options 객체

| 옵션 | 타입 | 기본값 | 설명 |
|------|------|--------|------|
| `browser_verify` | bool | `true` | Reflected XSS 후보를 Playwright로 alert 실행 검증 |
| `stored_xss` | bool | `true` | HTTP 기반 Stored XSS 탐지 |
| `dom_hash_xss` | bool | `true` | hash/fragment 기반 DOM XSS 검증 |
| `dom_stored_xss` | bool | `false` | Playwright 기반 DOM Stored XSS 검증. 실제 form submit 가능성이 있어 기본 비활성화 |
| `timeout` | int | `10` | HTTP 요청 타임아웃 (초) |
| `verify_tls` | bool | `false` | TLS 인증서 검증 여부 |

---

## urls 객체 상세 필드

`urls` 리스트의 각 항목을 객체로 지정하면 파라미터, 메서드, 인증, Stored XSS 체크 URL까지 세밀하게 제어할 수 있습니다.

| 필드 | 타입 | 기본값 | 설명 |
|------|------|--------|------|
| `url` | string | **(필수)** | 테스트할 URL |
| `method` | string | `"GET"` | HTTP 메서드 (`"GET"` 또는 `"POST"`) |
| `params` | dict | URL 쿼리 자동 파싱 | 테스트할 파라미터와 기본값 |
| `headers` | dict | — | 해당 URL에만 적용할 헤더 |
| `cookies` | dict | — | 해당 URL에만 적용할 쿠키 |
| `type` | string | `"page"` | `"page"`, `"form"`, `"dom_hash"` |
| `safe_to_submit` | bool | `false` | `true`면 Stored / DOM Stored XSS 검증에서 실제 form submit 허용 |
| `check_urls` | list\<string\> | — | Stored XSS 검증 시 마커를 찾을 URL 목록 |
| `body_format` | string | `"form"` | POST body 포맷: `"form"` (form-encoded) 또는 `"json"` |

---

## 기능별 필요한 입력

| 기능 | 필요한 입력 |
|------|-------------|
| **Reflected XSS — GET 파라미터** | `spider_urls` / `fuzzer_urls` (쿼리 파라미터 포함) 또는 `urls[]` (GET, params) |
| **Reflected XSS — POST 파라미터** | `urls[]`에 `method: "POST"`, `params` 설정 |
| **Reflected XSS — HTTP 헤더** | 어떤 URL이든 타겟으로 지정 시 자동 테스트 (Referer, User-Agent, X-Forwarded-For, X-Forwarded-Host) |
| **브라우저 검증 (alert hook 확인)** | `options.browser_verify: true` + Reflected 후보 존재 |
| **Stored XSS (HTTP)** | `stored_targets[]` 또는 `urls[]`에 `method: "POST"`, `safe_to_submit: true`, `params` 설정 + `check_urls` 권장 |
| **DOM Hash XSS** | `urls[]`에 `type: "dom_hash"` 또는 fragment(`#`) 포함 URL |
| **DOM Stored XSS (브라우저)** | `urls[]`에 `type: "form"`, `safe_to_submit: true` |
| **WAF 우회 시도** | 스캐너가 WAF 감지 시 자동 시도 (별도 입력 불필요) |
| **세션 인증** | `session_id` 또는 `token` (top-level) |
| **로그인 모의 인증** | `login_mock.json` 파일 생성 (`session_id`, `token` 키 포함) |

> `safe_to_submit: true` 없이는 Stored / DOM Stored 검증에서 실제 데이터를 전송하지 않습니다. 운영 데이터가 오염되는 것을 방지하기 위한 안전장치입니다. 이 값은 자동 추론하지 않으며, 입력 JSON에 명시된 경우에만 허용됩니다.

---

## 입력 예시

```json
{
  "base_url": "https://target.example.com",

  "spider_urls": [
    "https://target.example.com/search?q=test",
    "https://target.example.com/news?id=1&cat=tech"
  ],

  "fuzzer_urls": [
    "https://target.example.com/api/items?name=abc"
  ],

  "urls": [
    {
      "url": "https://target.example.com/comment",
      "method": "POST",
      "params": {
        "comment": "hello",
        "name": "tester"
      }
    },
    {
      "url": "https://target.example.com/profile",
      "method": "GET",
      "type": "form",
      "safe_to_submit": true,
      "params": {
        "display_name": "tester"
      }
    },
    {
      "url": "https://target.example.com/widget#section1",
      "type": "dom_hash"
    }
  ],

  "stored_targets": [
    {
      "url": "https://target.example.com/comment",
      "method": "POST",
      "body_format": "form",
      "safe_to_submit": true,
      "params": {
        "comment": "hello",
        "name": "tester"
      },
      "check_urls": [
        "https://target.example.com/board/1"
      ]
    }
  ],

  "headers": {
    "X-Custom-Header": "test"
  },
  "cookies": {
    "lang": "ko"
  },

  "session_id": "abc123sessionvalue",

  "options": {
    "browser_verify": true,
    "stored_xss": true,
    "dom_hash_xss": true,
    "dom_stored_xss": false,
    "timeout": 10,
    "verify_tls": false
  }
}
```

### login_mock.json 예시 (인증이 필요한 경우)

```json
{
  "session_id": "your-session-cookie-value",
  "token": "Bearer eyJhbGci..."
}
```

`login_mock.json`을 수동으로 수정하거나, `xss_module/login.py`의 `get_auth()` 함수를 실제 로그인 로직으로 교체하세요.

---

## 결과 구조

```json
{
  "status": "ok",
  "result_type": "final",
  "complete": true,
  "module": "xss_module",
  "version": "2.1-lightweight",
  "base_url": "https://target.example.com",
  "timestamp": "2026-05-06T15:28:59",
  "summary": {
    "total_targets": 5,
    "total_findings": 2,
    "high": 1,
    "medium": 1,
    "low": 0,
    "info": 0,
    "errors": 0,
    "skipped": 0
  },
  "scope": {
    "supported": [],
    "excluded_or_limited": [],
    "options": {}
  },
  "results": [
    {
      "type": "reflected_xss_candidate",
      "url": "...",
      "method": "GET",
      "param": "q",
      "payload": "<script>alert(1)</script>",
      "context": "html_body",
      "risk": "HIGH",
      "browser_verified": true,
      "verification_status": "verified",
      "evidence": {
        "alert_triggered": true,
        "alert_text": "alert:1",
        "executed_payload": "<script>alert(1)</script>",
        "target_url": "https://target.example.com/search?q=...",
        "verification_method": "browser_playwright"
      }
    }
  ],
  "skipped": [],
  "errors": []
}
```

### 결과 type 목록

| type | 설명 |
|------|------|
| `reflected_xss_candidate` | GET 파라미터 Reflected XSS 후보 |
| `reflected_xss_post_candidate` | POST 파라미터 Reflected XSS 후보 |
| `header_reflected_xss_candidate` | HTTP 헤더 Reflected XSS 후보 |
| `stored_xss_candidate_limited` | HTTP 기반 Stored XSS 후보 |
| `dom_hash_xss_verified` | hash/fragment DOM XSS (브라우저 검증 완료) |
| `dom_stored_xss_confirmed` | DOM Stored XSS (브라우저 검증 완료) |
| `stored_xss_skipped` | `safe_to_submit` 미허용으로 HTTP Stored XSS 제출 생략 |
| `dom_stored_xss_skipped` | `safe_to_submit` 미허용으로 DOM Stored XSS 제출 생략 |

### verification_status

| status | 의미 |
|------|------|
| `verified` | 브라우저 hook으로 JS 실행 확인 |
| `not_triggered` | 브라우저 검증은 수행됐지만 alert hook 미발생 |
| `skipped` | 안전 정책 또는 옵션 때문에 검증 생략 |
| `browser_error` | Playwright 실행 또는 브라우저 처리 오류 |
| `timeout` | navigation / selector / verification timeout |
| `auth_failed` | 인증 실패로 검증 불가 |
| `selector_not_found` | DOM Stored 검증 중 채울 수 있는 입력 필드 없음 |
| `submit_failed` | DOM Stored 검증 중 submit 경로 없음 |

### risk 수준

| risk | 의미 |
|------|------|
| `HIGH` | `browser_verified: true` 및 `verification_status: "verified"`로 브라우저 실행 확인됨 |
| `MEDIUM` | 반사 확인, 브라우저 검증 필요 |
| `LOW` | 반사는 확인됐으나 인코딩/이스케이프 처리됨 |

---

## 범위 및 제한

**지원:**
- GET / POST 파라미터 Reflected XSS 후보 탐지
- HTTP 헤더(Referer, User-Agent, X-Forwarded-For, X-Forwarded-Host) Reflected XSS
- Playwright 기반 window.alert hook 실행 검증
- screenshot/dialog/manual review 없이 headless 브라우저에서 JS 실행 여부만 검증
- WAF 감지 및 우회 페이로드 시도
- CSRF 토큰 자동 추출 및 주입
- `#fragment` 기반 DOM XSS 검증
- `safe_to_submit` 폼 대상 Stored XSS 후보 탐지
- Playwright 기반 DOM Stored XSS (localStorage 재방문 패턴)

**제외/제한:**
- 전체 DOM XSS data-flow 분석 미구현
- `safe_to_submit: true` 없이는 Stored / DOM Stored 검증에서 실제 데이터 전송 없음
- 로그인이 필요한 경우 `session_id` / `token` / `login_mock.json` 수동 설정 필요
- 대량 페이로드 fuzzing 미구현 (경량 탐지 목적)
