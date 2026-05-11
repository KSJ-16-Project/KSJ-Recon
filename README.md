# sql_injection 모듈

통합 자동화 취약점 진단 파이프라인의 SQL Injection 탐지 모듈.
직접 익스플로잇이 아닌 **DBMS 핑거프린팅 + 공격 가능 기법 도출**이 목적이며, 결과를 Core에 전달한다.

---

## 파이프라인 위치

```
Entry → Crawler / Nmap / Fuzzer → Middle → 전처리 LLM → [SQLi 모듈] → Core → 시나리오 LLM → 보고서
```

---

## 파일 구조

```
sql_injection/
├── __init__.py       공개 API (run_scan, ScanInput, ScanOutput, Endpoint 등 export)
├── models.py         입출력 데이터 타입
├── payloads.py       페이로드 + 참고 쿼리 데이터
├── prober.py         HTTP 요청 엔진 (send_probe, CSRF 토큰 취득, 헤더/쿠키 빌드)
├── fingerprint.py    Phase 0~2 DBMS 탐지
├── version.py        Phase 3 버전 추출
└── scanner.py        오케스트레이션 (run_scan)
```

---

## 탐지 흐름

```
Phase 0: nmap_data 유효 → 즉시 DBMS 확정 (요청 0회, confidence: HIGH)
Phase 1: ERROR_PROBES 동시 전송 → 에러 패턴 매칭 (confidence: HIGH)
Phase 2: BOOLEAN_PROBES 참/거짓 쌍 → 응답 차이 감지 (confidence: MEDIUM)
          string context 실패 → integer context 자동 fallback
Phase 3: injectable params 에만 VERSION_PROBES 적용
          1차: boolean (string context)
          2차: boolean (integer context fallback)
          3차: 에러 메시지 파싱 (boolean 불가 환경 대응)
```

순회 단위는 **endpoint 1개**이며, 사이트 전체 SQLi 표면을 훑기 위해 모든 endpoint를 순회한다.
DBMS가 확정된 후에도 injectable params 누적 수집은 계속된다.

---

## 지원 DBMS

MySQL / PostgreSQL / MSSQL / Oracle / SQLite

---

## 입출력

### 입력 (ScanInput)

| 필드 | 타입 | 설명 |
|------|------|------|
| `target_url` | `str` | 스캔 대상 사이트의 대표 URL |
| `endpoints` | `list[Endpoint]` | 한 번의 요청 단위로 묶인 파라미터 묶음 배열 |
| `auth` | `dict[str, str]` | 인증 정보 (cookie, Referer 등) |
| `nmap_data` | `NmapDBInfo \| None` | Nmap DBMS 정보 |

#### Endpoint

| 필드 | 타입 | 설명 |
|------|------|------|
| `url` | `str` | GET URL 또는 POST 폼 action URL |
| `method` | `str` | `"GET"` 또는 `"POST"` |
| `enctype` | `str` | `""`(GET) / `"application/x-www-form-urlencoded"` / `"multipart/form-data"` / `"application/json"` |
| `params` | `list[Parameter]` | 함께 전송될 파라미터 묶음 (POST 폼은 hidden 포함 모든 필드) |

#### 입력 JSON 예시

```json
{
  "target_url": "https://example.com/",
  "auth": {
    "cookie": "session=abc; csrftoken=xyz",
    "Referer": "https://example.com/"
  },
  "nmap_data": { "port": 0, "service": "", "version": "" },
  "endpoints": [
    {
      "url": "https://example.com/board/view.php",
      "method": "GET",
      "enctype": "",
      "params": [
        { "name": "idx", "location": "query", "value": "88" }
      ]
    },
    {
      "url": "https://example.com/_action/faq.do.php",
      "method": "POST",
      "enctype": "multipart/form-data",
      "params": [
        { "name": "con_title",  "location": "body", "value": "" },
        { "name": "con_writer", "location": "body", "value": "" },
        { "name": "Mode",       "location": "body", "value": "add_faq" }
      ]
    }
  ]
}
```

`auth["cookie"]`는 `"session=abc; csrftoken=xyz"` 형식의 문자열.
나머지 `auth` 키는 HTTP 헤더로 자동 추가된다.
`params[].value`는 관측값 또는 빈 문자열 — 모듈은 `value + payload` 방식으로 주입하므로 빈 값이어도 페이로드는 정상 실행된다.

### 출력 (ScanOutput)

```json
{
  "dbms_type": "MSSQL",
  "dbms_version": "2012",
  "confidence": "high",
  "injectable_params": [
    {"param": "top",       "url": "http://.../shop_topview.asp",   "method": "GET"},
    {"param": "g_code",    "url": "http://.../shop_goodsview.asp", "method": "GET"},
    {"param": "con_title", "url": "http://.../_action/faq.do.php", "method": "POST"}
  ],
  "technique_queries": {
    "confirmed": {
      "Error-based": ["'", "' OR sqlspider"]
    },
    "possible": {
      "Union-based": ["' UNION SELECT NULL-- -"],
      "Stacked queries": ["'; WAITFOR DELAY '0:0:1'-- -"]
    }
  },
  "auth_expired": false
}
```

- `injectable_params` 항목은 `(param, url, method)` 트리플 단위로 누적되며 중복 제거됨
- `to_dict()` / `to_json()` 출력에는 `probe_log`가 포함되지 않음 (대용량이라 제외)
- `auth_expired=true`는 모든 endpoint가 세션 만료/재로그인 불가로 막혔음을 의미

---

## 테스트 실행

```bash
# kisec — MySQL, GET, string context
~/.venv/bin/python test.py

# oyes — MSSQL, POST, body params
~/.venv/bin/python oyes_test.py

# JSON 입출력 테스트
~/.venv/bin/python test_json.py

# Login 모듈 통합 테스트
~/.venv/bin/python test_login_integration.py
```

> **알림**: `endpoints[]` 입력 스키마 마이그레이션 이후 통합 사이트 검증은
> 테스트 사이트 접근 불가로 보류 중. 모듈 단위 동작은 확인 완료.

---

## Core 연동

```python
import asyncio
import ksj_login
from sql_injection import run_scan, ScanInput

# 1) 자격증명 저장 (Core 시작 시 1회)
ksj_login.store_credentials(login_url, user_id, password)

# 2) 첫 세션 발급
auth_result = await ksj_login.get_session()
sql_data["auth"] = {"cookie": ksj_login.to_cookie_header(auth_result.cookies)}

# 3) 스캔 실행
scan_input = ScanInput.from_dict(sql_data)
sqli_result = await run_scan(scan_input)
mid_core.get_sqli_data(sqli_result.to_dict())
```

---

## Login 모듈 연동

`scanner.py`가 세션 만료(401/403/302)를 감지하면 `ksj_login` 모듈을 직접 호출해
새 세션을 받아온다. **별도 콜백 등록은 필요 없다.**

```python
# scanner.py 내부 동작 (참고)
async def _try_relogin() -> dict[str, str] | None:
    if not ksj_login.has_credentials():
        return None
    auth_result = await ksj_login.get_session()
    if not auth_result.success:
        return None
    return {"cookie": ksj_login.to_cookie_header(auth_result.cookies)}
```

**세션 처리 흐름**:
1. endpoint 요청 → 401/403/302 감지 → `_try_relogin()` 호출
2. 자격증명 있고 재로그인 성공 → 새 쿠키로 같은 endpoint 재시도
3. 재시도도 실패 → 해당 endpoint 스킵, 다음 endpoint 계속
4. 자격증명 없거나 재로그인 실패 → 해당 endpoint만 스킵 + `auth_expired=True` 플래그 → 공개 endpoint는 정상 시도
5. 모든 endpoint가 막힘 → 빈 결과 + `auth_expired=True`

자격증명이 없어도 즉시 종료하지 않으며, 가능한 endpoint는 끝까지 시도한다.

---

## 변경 이력

### 9차 — 입력 스키마 개편 (`endpoints[]`)

`crawler_data` + `fuzzer_data` 평면 입력을 폐기하고 **`endpoints[]` 묶음 단위로 통합**.
한 endpoint = "한 번의 요청에 같이 보내야 할 파라미터 묶음".

해결한 문제:
- POST 폼이 1필드만 전송돼 백엔드 검증에서 reject되던 문제 (`prober._inject_param`이 폼 hidden 포함 전체 필드 동봉)
- POST 폼 action URL이 입력에 누락되던 문제 (`endpoints[]` 스키마로 흡수)
- `injectable_params` 출력의 (param, url) 매핑 손실 (출력에 `method` 키 추가, `(param, url, method)` 트리플 기준 중복 제거)

파일별 변경:
- `models.py` — `Endpoint` dataclass 신설, `ScanInput`을 `target_url + endpoints + auth + nmap_data`로 교체
- `prober.py` — `_inject_param`에 `all_params` 인자 추가, `send_probe`/`send_probes_concurrent`에 `enctype` + multipart/json/urlencoded 분기
- `fingerprint.py` / `version.py` — `enctype`, `all_params` 패스스루, baseline·error fallback도 enctype 분기
- `scanner.py` — endpoint 단위 순회로 전면 재작성, `best_endpoint` 추적해 Phase 3가 같은 폼 묶음 재사용
- `__init__.py` — `Endpoint` export

### 10차 — 입력 강건성 + CSRF 토큰 범위 확장

해결한 문제:
- LLM이 `params[].location`에 잘못된 값(빈 문자열, `unknown` 등)을 보내도 `ScanInput.from_dict()` 자체가 실패하지 않도록 강건화 → 해당 파라미터만 조용히 스킵
- Phase 1만 CSRF 토큰을 자동 취득하고 Phase 2(boolean) · Phase 3(version)는 별도 client를 만들어 토큰 없이 진행하던 결함 → POST + CSRF 토큰 사이트에서 reject 발생

파일별 변경:
- `models.py` — `from_dict`의 `params` 컴프리헨션에 location 필터 한 줄 추가
- `fingerprint.py` — `_run_boolean_phase`가 client 직후 POST/BODY 조건이면 `fetch_csrf_token()` 1회 호출, `send_probe`에 토큰 패스
- `version.py` — `extract_version` 체인 전체에 `csrf_tokens` 인자 전파. baseline·error probe는 `body.update(csrf_tokens)`, version probe는 `send_probe` 패스

추가 비용: endpoint 당 POST/BODY 조건일 때만 최대 3회 GET (Phase 2 ×2 + Phase 3 ×1). 순수 GET endpoint는 0회.

### 출력 스키마 변경

```diff
- injectable_params: [{"param": str, "url": str}]
+ injectable_params: [{"param": str, "url": str, "method": str}]
```

### 동반 문서

- `CLAUDE.md` — 9차/10차 수정 내역, 입출력 명세, 잠재적 개선 항목, 핵심 함수 시그니처 갱신
- `preprocess_prompt_endpoints_spec.md` (신규) — LLM 측 전처리 프롬프트 수정 명세서. `params[].value` 정책 = "관측값 또는 빈 문자열" (더미 `"test"` 금지)

### 검증 상태

단위 검증 통과 (import / `from_dict` / `_inject_param` 폼 묶음 / 빈 endpoints 가드 / location 필터). 실제 사이트 통합 테스트는 환경 정비 후 진행 예정.

### 의도적 보류 (잠재적 개선, 치명적 아님)

- `best_result` 갱신이 confidence 무시 (`scanner.py:185-190`)
- `_inject_param`이 COOKIE/HEADER 타겟 + POST endpoint면 body 누락 (드문 케이스)
- `auth_expired` 응답이 `confirmed["Error-based"]`에 잘못 포함될 가능성 (확률 매우 낮음)
