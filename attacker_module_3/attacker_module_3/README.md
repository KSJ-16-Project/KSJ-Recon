# DAST Attacker — SSRF & File Download 공격 모듈

상위 DAST 스캐너에 임베드해 사용하는 Python 3 공격 모듈 묶음. 세 개의 형제
패키지로 구성된다.

- [`common/`](common/README.md) — 공통 인프라(HTTP 클라이언트, 자료형, JSON
  입출력 계약, 인젝터/디텍터, `AttackModule` 베이스). 페이로드는 들어 있지
  않다.
- [`ssrf/`](ssrf/README.md) — `SSRFModule` 과 SSRF 페이로드 카탈로그.
- [`file_download/`](file_download/README.md) — `FileDownloadModule`(경로 순회/
  LFI)과 페이로드 카탈로그.

각 공격 모듈은 인-프로세스 import API 와 **JSON-in / JSON-out** 진입점을
함께 노출한다. CLI 는 제공하지 않으며, 부모 오케스트레이터가 직접 호출한다.

## 디렉토리 구성

```
attacker_module_3/
├── pyproject.toml          # 워크스페이스 선언 — 세 패키지 모두 등록
├── requirements.txt
├── conftest.py             # 임시로 띄우는 테스트용 HTTP 서버
├── scan.py                 # 부모 DAST 없이 모듈을 직접 실행하는 임시 스크립트
├── README.md               # (이 문서)
│
├── common/
│   ├── README.md
│   ├── target.py           # Target 자료형 + JSON/YAML 로더
│   ├── http.py             # HttpClient (requests.Session 래퍼)
│   ├── result.py           # Severity / Confidence / Finding / ScanReport
│   ├── injector.py         # GET/POST 파라미터 치환
│   ├── detector.py         # 응답 시그니처 매칭 + 베이스라인 비교
│   ├── base.py             # AttackModule 추상 클래스 + run_json 진입점
│   ├── exceptions.py       # AuthenticationError 등 공통 예외 클래스
│   ├── io.py               # JSON 요청/응답 직렬화
│   └── tests/
│
├── ssrf/
│   ├── README.md
│   ├── payloads.py         # SSRFPayload 카탈로그 (2종)
│   ├── module.py           # SSRFModule
│   ├── samples/targets.yaml
│   └── tests/
│
└── file_download/
    ├── README.md
    ├── payloads.py         # PathPayload 카탈로그 (6종)
    ├── module.py           # FileDownloadModule
    ├── samples/targets.yaml
    └── tests/
```

## 요구 환경

- Python **3.10 이상**
- 외부 의존성: `requests>=2.32`, `PyYAML>=6.0`
- 테스트: `pytest>=7`

## 설치

```sh
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

`pip install -e .` 가 워크스페이스의 세 패키지(`common`, `ssrf`,
`file_download`)를 모두 import 가능 상태로 만든다.

## 사용법

### 1. 인-프로세스 API

같은 파이썬 프로세스 안에서 직접 호출하는 경로.

```python
from common import HttpClient, Target
from ssrf import SSRFModule
from file_download import FileDownloadModule

http = HttpClient(timeout=10.0, verify=True)
target = Target(
    url="https://example.com/download",
    method="GET",
    params={"id": "1"},
    inject_params=["id"],
)

findings  = SSRFModule(http=http, max_workers=8).run(target)
findings += FileDownloadModule(http=http, max_workers=8).run(target)

for f in findings:
    print(f.severity.value, f.title, f.payload)
```

`run()` 은 인증 실패(401/403) 시 `AuthenticationError` 를 발생시킨다. 호출자가
직접 처리해야 한다.

```python
from common import AuthenticationError

try:
    findings = SSRFModule(http=http, max_workers=8).run(target)
except AuthenticationError as e:
    print(f"인증 실패 (HTTP {e.status_code}) — 토큰을 갱신하세요.")
```

### 2. JSON-in / JSON-out

부모 DAST 오케스트레이터가 사용하는 표준 경로. 입출력 모두 JSON 문서 한 개씩
오가며, 전송 수단은 부모가 자유롭게 선택한다(파이프, 메시지 큐, HTTP, 같은
프로세스 내 함수 호출 등).

요청:

```json
{
  "target": {
    "url": "https://example.com/download",
    "method": "GET",
    "params":  {"id": "1"},
    "inject_params": ["id"]
  },
  "options": {"max_workers": 8, "timeout": 10.0}
}
```

응답(예시):

```json
{
  "module": "ssrf",
  "target_url": "https://example.com/download",
  "started_at":  "2026-05-01T08:30:00.000Z",
  "finished_at": "2026-05-01T08:30:00.500Z",
  "stats": {"requests": 2, "errors": 0, "elapsed_ms": 487.2},
  "findings": [{
    "module": "ssrf",
    "severity": "critical",
    "confidence": "high",
    "title": "SSRF via id: scheme-file-nix",
    "parameter": "id",
    "payload": "file:///etc/passwd",
    "evidence": "root:x:0:0",
    "request":  {"url": "...", "method": "GET", "params": {...}, "data": null},
    "response": {"status": 200, "elapsed_ms": 87.1, "length": 102}
  }]
}
```

호출 코드:

```python
import json
from ssrf import SSRFModule

response_json = SSRFModule.run_json(json.dumps({
    "target": {
        "url": "https://example.com/download",
        "method": "GET",
        "params": {"id": "1"},
        "inject_params": ["id"],
    },
    "options": {"max_workers": 8},
}))
```

JSON 의 `null` 값은 "값 미지정"으로 해석되어 모듈 디폴트로 떨어진다. 알 수
없는 키는 즉시 `ValueError` 로 거절돼 계약 표류를 조기에 잡는다.

`run_json()` 은 정상 응답 외에 두 가지 에러 응답을 반환할 수 있다.

| `error` 값 | 원인 | 부모 DAST 대응 |
|---|---|---|
| `auth_required` | 스캔 중 401/403 수신 — 토큰 만료 | 로그인 모듈 호출 후 재시도 |
| `invalid_request` | 요청 JSON 구조 오류 | 요청 형식 점검 |

```json
{"error": "auth_required", "status_code": 401}
```

## 모듈 한눈에 보기

| 모듈 | 페이로드 수 | 무엇을 탐지하는가 | 자세한 설명 |
|---|---|---|---|
| `ssrf` | 2 | `file://` 스킴을 통한 시스템 파일 회수 (Linux/Windows) | [ssrf/README.md](ssrf/README.md) |
| `file_download` | 6 | 경로 순회로 `/etc/passwd`, `/proc/self/environ`, Windows `win.ini` 회수 | [file_download/README.md](file_download/README.md) |

탐지 기준은 두 모듈 모두 동일하다 — **응답 본문에 시스템 파일 시그니처가
포함됐는가**. 시간 측정 / OAST 같은 추측성 탐지는 의도적으로 배제했다.

## scan.py — 부모 DAST 없이 직접 실행

부모 DAST 연동 전에 모듈을 단독으로 실행해 볼 수 있는 임시 스크립트.
`TARGETS` 리스트만 수정하면 된다.

```powershell
cd "C:\Projects\ksj\KSJ-Recon\attacker_module_3"
python scan.py
```

인증 오류(401/403)는 메시지를 출력하고 다음 대상으로 넘어간다. Ctrl+C 로
언제든 중단할 수 있다. 부모 DAST 연동 후에는 삭제해도 무방하다.

## 빌드 & 테스트

```sh
pytest
python -m compileall common ssrf file_download
```

테스트는 인-프로세스 `http.server.ThreadingHTTPServer` 를 `127.0.0.1` 에만
바인딩해 사용한다. `pytest` 실행 중 어떤 요청도 루프백을 벗어나지 않는다.

## 안전 기본값

- `allow_redirects=False` — 프로브가 다른 호스트로 튀어나가지 않도록 차단.
- 응답 본문 64 KiB 상한 — 시그니처 검사 시 메모리 보호.
- `verify=True` — TLS 검증은 기본 활성. `verify=False` 는 명시적으로 줄 때만.
- 요청별 타임아웃 기본 10초, `Target.timeout` 으로 개별 덮어쓰기 가능.
- `HttpClient.scope_predicate` — 부모 DAST 가 화이트리스트를 강제할 수 있게
  하는 콜백 후크.
- OAST(Burp Collaborator 류) / DNS 콜백 탐지는 의도적으로 범위 밖.

## 새로운 공격 모듈 추가

`xss/`, `sqli/` 같은 형제 패키지를 추가하는 방법은 [`common/README.md`](common/README.md)
의 "새로운 공격 모듈 추가하기" 절을 참고한다. 베이스 클래스가 실행 파이프라인을
모두 처리하므로 하위 클래스는 `_probes` 와 `_build_finding` 두 메서드만 구현하면
된다.

## 라이선스

MIT License — 자세한 내용은 [`LICENSE`](LICENSE) 파일 참고.
