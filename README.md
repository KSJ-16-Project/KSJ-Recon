# piscovery — SQL Injection Detection Module

piscovery 자동화 취약점 진단 파이프라인의 **SQL Injection 탐지 모듈**입니다.

직접 공격이 아니라 **DBMS 핑거프린팅 + 공격 가능 기법 도출**이 목적이며, 결과를 시나리오 생성 LLM에 구조화된 JSON으로 전달합니다.

```
Entry → Crawler / Nmap / Fuzzer → Middle → 전처리 LLM → [SQLi 모듈] → 시나리오 LLM → 보고서
```

---

## 탐지 흐름

```
Phase 0  Nmap 포트/서비스 → 즉시 DBMS 확정
Phase 1  에러 유발 페이로드 → 응답 에러 패턴 매칭        (confidence: HIGH)
Phase 2  Boolean 페이로드 참/거짓 → 응답 차이 감지       (confidence: MEDIUM)
Phase 3  버전 추출
           1차. Boolean string context
           2차. Boolean integer context fallback
           3차. 에러 메시지 파싱 fallback
```

- 각 Phase는 성공 시 즉시 중단 (조기 종료)
- string context 실패 시 integer context 자동 fallback
- 지원 DBMS: MySQL / PostgreSQL / MSSQL / Oracle / SQLite

---

## 설치 및 실행

```bash
# 의존성 설치
pip install httpx

# 테스트 실행
python test.py           # kisec (MySQL, GET)
python oyes_test.py      # oyes (MSSQL, POST)
python test_json.py      # preprosess_data.json 기반 (JSON 입출력)
```

---

## 사용법

```python
import asyncio
import json
from sql_injection import run_scan, ScanInput

async def main():
    with open("preprosess_data.json", encoding="utf-8-sig") as f:
        data = json.load(f)

    scan_input = ScanInput.from_dict(data["sql_data"])
    result = await run_scan(scan_input)

    print(result.to_json())

asyncio.run(main())
```

---

## 입력 형식 (ScanInput JSON)

```json
{
  "target_url": "https://example.com/page",
  "crawler_data": [
    { "name": "id", "location": "query", "value": "86" },
    { "name": "keyword", "location": "body", "value": "test" }
  ],
  "auth": {
    "cookie": "session=abc; csrftoken=xyz",
    "Referer": "https://example.com/"
  },
  "nmap_data": { "port": 3306, "service": "mysql", "version": "" },
  "fuzzer_data": [
    "https://example.com/hidden/endpoint"
  ]
}
```

| 필드 | 설명 |
|---|---|
| `target_url` | 스캔 대상 URL |
| `crawler_data` | 파라미터 목록. `location`: query / body / cookie / header |
| `auth` | 인증 데이터. `cookie` 키만 특별처리, 나머지는 HTTP 헤더로 자동 추가. 빈 값 키는 자동 제외 |
| `nmap_data` | Nmap DB 포트 정보. 없으면 port/service/version 빈 값으로 전달 |
| `fuzzer_data` | Fuzzer가 발견한 추가 엔드포인트 URL 목록 |

---

## 출력 형식 (ScanOutput JSON)

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
      "Info gathering": ["SELECT @@version"]
    }
  },
  "probe_log": [...],
  "auth_expired": false
}
```

| 필드 | 설명 |
|---|---|
| `dbms_type` | 탐지된 DBMS 종류 |
| `dbms_version` | 탐지된 메이저 버전 (탐지 실패 시 null) |
| `confidence` | 탐지 신뢰도: high / medium / low |
| `injectable_params` | 주입 가능 확인된 파라미터 이름 목록 |
| `technique_queries.confirmed` | 실제 반응 확인된 기법 + 유효 페이로드 |
| `technique_queries.possible` | 환경 조건 기반 가능 기법 + 참고 쿼리 |
| `probe_log` | 전체 요청 기록 |
| `auth_expired` | True면 오케스트레이터가 Login 모듈 재호출 |

---

## 파일 구조

```
sql_injection/
├── __init__.py       공개 API
├── models.py         입출력 타입 정의
├── payloads.py       페이로드 및 참고 쿼리 데이터
├── prober.py         HTTP 요청 엔진
├── fingerprint.py    Phase 0~2 DBMS 탐지
├── version.py        Phase 3 버전 추출
└── scanner.py        오케스트레이션
```

---

## 설계 원칙

**Boolean 프로브는 DBMS별 시스템 카탈로그 참조**
범용 `1=1` / `1=2` 방식은 모든 DBMS에서 동일하게 반응해 DBMS 구분이 불가능하다. DBMS 고유 시스템 테이블을 참조해 다른 DBMS에서는 에러로 양쪽 응답이 같아지도록 설계했다.

**CSRF 토큰 처리는 Login 모듈 책임**
현재는 POST 요청 시 직접 CSRF 토큰을 취득하는 임시 구현이다. Login 모듈 구현 완료 후 `auth["csrf_token"]` 기반으로 교체 예정. `[TEMP]` / `[FUTURE]` 주석 위치 참조.

**auth_expired 신호**
세션 만료 또는 CSRF 검증 실패(401/403)가 감지되면 스캔을 즉시 중단하고 `auth_expired: true`를 반환한다. 오케스트레이터가 Login 모듈을 재호출해 새 인증 데이터를 받아오는 구조다.

---

## 요구사항

- Python 3.12+
- httpx

---

## 참고 자료

페이로드 및 에러 패턴 출처:
- Nmap NSE scripts (`http-sql-injection.nse`, `mssql.lua`, `mysql-databases.nse` 등)
- fuzzdb (`http-sql-errors.lst`)
