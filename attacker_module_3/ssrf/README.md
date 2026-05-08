# ssrf — SSRF(Server-Side Request Forgery) 모듈

서버가 사용자 입력을 그대로 받아 외부/내부 자원을 가져오게 하는 SSRF 취약점을
탐지한다. URL 을 받는 파라미터(`url`, `target`, `image`, `feed` 등)에 미리
준비된 페이로드를 끼워 넣고, 응답 본문에 **명백히 SSRF 가 성공했음을 증명하는
시그니처**가 들어 있는지 확인한다.

## 무엇을 탐지하는가

대상 서버에 `file://` 스킴을 처리시켜 자기 자신의 파일시스템을 읽게 만드는
SSRF 한 가지에만 집중한다. OS 별로 두 가지 변형:

- **Linux** — `file:///etc/passwd` → 시그니처 `b"root:x:0:0"`
- **Windows** — `file:///c:/windows/win.ini` → 시그니처 `b"[fonts]"`,
  `b"[extensions]"`

탐지 기준은 단 하나, **응답 본문에 시스템 파일 시그니처가 나타나는가**이다.
시간 차이 측정, 블라인드 SSRF (out-of-band) 같은 추측성 탐지는 의도적으로
배제했다 — 거짓 양성(False Positive)을 거의 0 에 가깝게 만들었다.

## 디렉토리 구성

```
ssrf/
├── __init__.py            # SSRFModule, SSRFPayload, PAYLOADS 공개
├── payloads.py            # SSRF 페이로드 카탈로그 (file:// 2종)
├── module.py              # SSRFModule(AttackModule) 본체
├── samples/
│   └── targets.yaml       # 데모용 대상 정의
└── tests/
    └── test_ssrf_module.py
```

## 동작 원리

1. **후보 파라미터 결정** — `Target.inject_params` 가 비어 있으면 GET 의
   `params` 또는 POST 의 `data` 의 키 전체가 자동으로 후보가 된다.
2. **Probe 생성** — `_probes()` 가 `(파라미터 × 페이로드)` 조합을
   `Probe` 객체로 만들어낸다.
3. **요청 송신** — `inject(target, payload, parameter)` 로 요청 인자를 빌드해
   `HttpClient.request(...)` 로 보낸다. 서버는 이 파라미터 값을 URL 로 해석해
   가져오기를 시도하므로, `file:///etc/passwd` 가 처리되면 그 응답이 우리한테
   그대로 돌아온다.
4. **시그니처 매칭** — 응답 본문에서 `b"root:x:0:0"` (Linux) 또는
   `b"[fonts]"` / `b"[extensions]"` (Windows) 토큰을 찾는다.
5. **Finding 생성** — 매칭이 발생하면 `Severity.CRITICAL` 의 finding 을 만든다.

```
[Target]
   │
   │ params={"url": "https://placeholder.local"}, inject_params=["url"]
   │
   ▼
[SSRFModule._probes]
   │   url=... × payload=file:///etc/passwd               ┐
   │   url=... × payload=file:///c:/windows/win.ini       ┘ 2 probes
   │
   ▼ (ThreadPool)
[HttpClient.request]
   │   서버가 페이로드 URL 을 fetch 하면 응답 본문에 시스템 파일 내용이 섞여
   │   들어온다.
   ▼
[match(body, signatures)]
   │   시그니처 매칭 성공 → Finding(severity=critical, …)
   ▼
[ScanReport.findings]
```

## 페이로드 카탈로그

`payloads.py` — 2개. 각 항목은 `(value, category, signatures, confidence)`.

| 카테고리 | 페이로드 값 | 시그니처 | 신뢰도 |
|---|---|---|---|
| `scheme-file-nix` | `file:///etc/passwd` | `b"root:x:0:0"` | HIGH |
| `scheme-file-windows` | `file:///c:/windows/win.ini` | `b"[fonts]"`, `b"[extensions]"` | HIGH |

### 새 페이로드 추가하기

`payloads.py` 의 `PAYLOADS` 튜플에 항목 한 줄 추가하면 끝. 모듈은 자동으로
모든 페이로드를 순회한다.

```python
SSRFPayload(
    value="http://internal.corp/admin",
    category="internal-corp",
    signatures=(b"<title>Admin Panel</title>",),
    confidence=Confidence.HIGH,
),
```

**좋은 시그니처의 조건**:

- 정상 응답에는 거의 등장하지 않을 만큼 특이해야 한다(거짓 양성 방지).
- 짧고 정확해야 한다 — `bytes` 단위 부분 문자열 매칭이므로 인코딩에 강건.
- 여러 토큰을 줄 수 있다 — 그중 하나만 매칭되면 finding 생성.

시그니처가 떠오르지 않는 페이로드(loopback `http://127.0.0.1/`, 인코딩된 IP
`http://2130706433/` 등)는 **추가하지 말 것**. 응답기반 탐지로는 거짓 양성이
너무 많다. 블라인드 SSRF 탐지가 필요하면 `common/detector.py` 의
`baseline_diff` 와 별도 OAST 후크를 도입하는 v2 작업이다.

## 사용 예시

### 인-프로세스 API

```python
from common import HttpClient, Target
from ssrf import SSRFModule

http = HttpClient(timeout=10.0)
target = Target(
    url="https://example.com/api/fetch",
    method="GET",
    params={"url": "https://placeholder.local"},
    inject_params=["url"],
)

for finding in SSRFModule(http=http, max_workers=8).run(target):
    print(finding.severity.value, finding.title, finding.payload)
```

### JSON-in / JSON-out (부모 DAST 가 쓸 경로)

```python
import json
from ssrf import SSRFModule

response_json = SSRFModule.run_json(json.dumps({
    "target": {
        "url": "https://example.com/api/fetch",
        "method": "GET",
        "params": {"url": "https://placeholder.local"},
        "inject_params": ["url"]
    },
    "options": {"max_workers": 8, "timeout": 10.0}
}))
report = json.loads(response_json)
```

응답 형식:

```json
{
  "module": "ssrf",
  "target_url": "https://example.com/api/fetch",
  "started_at": "2026-05-01T08:30:00.000Z",
  "finished_at": "2026-05-01T08:30:00.500Z",
  "stats": {"requests": 2, "errors": 0, "elapsed_ms": 240.4},
  "findings": [{
    "module": "ssrf",
    "severity": "critical",
    "confidence": "high",
    "title": "SSRF via url: scheme-file-nix",
    "parameter": "url",
    "payload": "file:///etc/passwd",
    "evidence": "root:x:0:0",
    "request": {"url": "...", "method": "GET", "params": {...}, "data": null},
    "response": {"status": 200, "elapsed_ms": 87.1, "length": 102}
  }]
}
```

## 한계와 경계

- 이 모듈은 **응답 본문 시그니처에 의존**한다. 대상이 SSRF 응답을 직접
  반환하지 않는 시나리오(블라인드 SSRF)는 탐지하지 못한다.
- HTTP 스킴(`http://internal/...`)으로 내부 호스트를 노리는 SSRF 는 응답 본문이
  대상 환경에 따라 달라 일반화된 시그니처를 만들 수 없으므로 카탈로그에서
  제외했다. 특정 내부 호스트가 표적이라면 환경별 페이로드 파일을 만들어 추가.
- DNS 리바인딩, gopher/dict 등 특수 페이로드는 운영 환경에서 성공률·거짓
  양성 트레이드오프가 좋지 않아 카탈로그에 두지 않았다.

## 테스트

```sh
pytest ssrf/tests
```

`conftest.py` 의 `fixture_server` 가 127.0.0.1 에 바인딩된 인-프로세스 HTTP
서버를 띄워 `file:///etc/passwd` / `file:///c:/windows/win.ini` 응답을 흉내
낸다. 실제 외부 호스트로 어떤 요청도 나가지 않는다.
