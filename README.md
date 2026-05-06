# sql_injection 모듈

piscovery 자동화 취약점 진단 파이프라인의 SQL Injection 탐지 모듈.  
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
├── __init__.py       공개 API (run_scan, ScanInput, ScanOutput 등 export)
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

---

## 지원 DBMS

MySQL / PostgreSQL / MSSQL / Oracle / SQLite

---

## 입출력

### 입력 (ScanInput)

| 필드 | 타입 | 설명 |
|------|------|------|
| `target_url` | `str` | 스캔 대상 URL |
| `crawler_data` | `list[Parameter]` | 크롤러가 수집한 파라미터 목록 |
| `auth` | `dict[str, str]` | 인증 정보 (cookie, Referer 등) |
| `nmap_data` | `NmapDBInfo \| None` | Nmap DBMS 정보 |
| `fuzzer_data` | `list[str]` | Fuzzer가 발견한 숨겨진 엔드포인트 URL 목록 |

`auth["cookie"]` 값은 `"session=abc; csrftoken=xyz"` 형식의 문자열.  
나머지 키는 HTTP 헤더로 자동 추가된다.

### 출력 (ScanOutput)

```json
{
  "dbms_type": "MSSQL",
  "dbms_version": "2012",
  "confidence": "high",
  "injectable_params": ["frmSearchWord"],
  "technique_queries": {
    "confirmed": {
      "Error-based": ["'", "' OR sqlspider"]
    },
    "possible": {
      "Union-based": ["' UNION SELECT NULL-- -"],
      "Stacked queries": ["'; WAITFOR DELAY '0:0:1'-- -"]
    }
  },
  "probe_log": [...],
  "auth_expired": false
}
```

`auth_expired=true` 시 오케스트레이터가 Login 모듈 재호출 후 `run_scan()` 재시도.

---

## 테스트 실행

```bash
# kisec — MySQL, GET, string context
~/.venv/bin/python test.py

# oyes — MSSQL, POST, body params
~/.venv/bin/python oyes_test.py

# preprosess_data.json 기반 JSON 입출력 테스트
~/.venv/bin/python test_json.py
```

### 예상 결과

| 테스트 | DBMS | 버전 | Confidence |
|--------|------|------|------------|
| kisec | MySQL | 5.x | MEDIUM |
| oyes | MSSQL | 2012 | HIGH |
| test_json | Unknown | - | LOW |

---

## Core 연동

```python
from sql_injection import run_scan, ScanInput

scan_input = ScanInput.from_dict({...})
sqli_result = asyncio.run(run_scan(scan_input))
mid_core.get_sqli_data(sqli_result.to_dict())
```

## Login 모듈 연동

```python
from sql_injection import run_scan, ScanInput

# 로그인 완료 후 to_cookie_header(auth_result.cookies) 결과를 auth 에 전달
auth = {"cookie": to_cookie_header(auth_result.cookies)}
scan_input = ScanInput.from_dict({..., "auth": auth, ...})
sqli_result = asyncio.run(run_scan(scan_input))

# 세션 만료 시 세션 갱신 후 재호출
if sqli_result.auth_expired:
    new_auth_result = await relogin(browser, auth_result)
    # auth 재구성 후 run_scan() 재호출
```
