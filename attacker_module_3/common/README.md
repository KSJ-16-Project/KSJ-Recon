# common — 공통 인프라

모든 공격 모듈이 공유하는 기반 코드. SSRF · File Download 모듈은 이 패키지의
`HttpClient`, `Target`, `Finding`, `AttackModule` 등을 그대로 가져다 쓴다.
**페이로드는 들어 있지 않다** — 공격 패턴은 각 공격 모듈 패키지에 있다.

## 디렉토리 구성

```
common/
├── __init__.py     # 외부에 노출되는 공개 API 모음
├── target.py       # 스캔 대상 자료형 + JSON/YAML 로더
├── result.py       # Severity / Confidence / Finding / ScanReport
├── http.py         # 스레드-안전 HTTP 클라이언트 래퍼
├── injector.py     # 파라미터에 페이로드를 끼워 넣어 요청 인자를 만드는 헬퍼
├── detector.py     # 응답 본문에서 시그니처를 찾아내는 헬퍼
├── exceptions.py   # AuthenticationError 등 공통 예외 클래스
├── io.py           # JSON 입출력 계약 — 부모 DAST 와의 통신 규약
├── base.py         # AttackModule 추상 클래스 — 모든 공격 모듈의 부모
└── tests/          # 단위 테스트
```

## 자료형 한눈에 보기

```
Target ────► AttackModule.run() ────► list[Finding]
                  │
                  ├── _candidate_params(target)     # 어떤 파라미터를 퍼징할지 결정
                  ├── _probes(target)               # (파라미터 × 페이로드) 후보 생성 — 하위 클래스 구현
                  ├── inject(target, payload, parameter)   # 요청 인자 빌드
                  ├── HttpClient.request(...)              # 실제 송신
                  ├── match(body, signatures)              # 응답 시그니처 검사
                  └── _build_finding(...)                  # 매칭 시 Finding 작성 — 하위 클래스 구현
```

## 핵심 개념

### Target — 스캔 대상

```python
@dataclass
class Target:
    url: str                              # 기본 URL (예: https://example.com/file)
    method: Literal["GET", "POST"] = "GET"
    params: dict[str, str] | None = None  # 쿼리 파라미터
    data:   dict[str, str] | None = None  # POST 본문 (form-encoded)
    headers: dict[str, str] | None = None
    inject_params: list[str] = []         # 어떤 파라미터에 페이로드를 끼워 넣을지
    timeout: float | None = None          # 요청별 타임아웃 (HttpClient 기본값 덮어씀)
```

`inject_params` 가 비어 있으면 GET 의 경우 `params` 의 모든 키, POST 의 경우
`data` 의 모든 키가 자동으로 후보가 된다. 명시적으로 채우면 그 키만 퍼징한다.

### Finding — 탐지 결과 한 건

```python
@dataclass
class Finding:
    module: str                   # "ssrf" | "file_download"
    severity: Severity            # critical / high / medium / low / info
    confidence: Confidence        # high / medium / low
    title: str
    target_url: str
    method: str
    parameter: str                # 퍼징했던 파라미터 이름
    payload: str                  # 사용된 페이로드 값
    evidence: str                 # 응답에서 매칭된 시그니처 문자열
    request:  dict                # 재현용 요청 정보
    response: dict                # 응답 메타 (status, length, elapsed_ms)
```

### ScanReport — 스캔 단위 보고서

`run_json()` 이 반환하는 JSON 의 직렬화 대상. `findings` 외에 시작/종료 시각과
통계(`requests`, `errors`, `elapsed_ms`)를 함께 담는다.

## 동작 흐름 — `AttackModule._run_with_report`

`base.py` 의 베이스 클래스가 모든 공격 모듈에 공통되는 실행 파이프라인을
다음 순서로 처리한다.

1. `_candidate_params(target)` — 퍼징할 파라미터 목록 결정.
2. 후보가 비어 있으면 즉시 빈 리포트 반환.
3. `_probes(target)` (하위 클래스 구현) — `Probe(parameter, payload, signatures, …)`
   객체들을 만들어낸다.
4. `payload_limit` 가 지정돼 있으면 앞에서부터 그만큼 슬라이스.
5. `ThreadPoolExecutor` 에 모든 probe 를 한 번에 제출.
6. 각 워커는 `_probe_one` 을 실행:
   - `inject(target, payload, parameter)` 로 요청 인자 빌드
   - `HttpClient.request(...)` 송신
   - 응답이 401/403 이면 `AuthenticationError` 발생 → 스캔 즉시 중단
   - 전송 실패면 `(resp_with_error, None)` 반환
   - 성공 시 `match(body, signatures)` — 매칭되면 `_build_finding` 호출
7. `as_completed` 로 결과를 모으며 통계 갱신. `KeyboardInterrupt` 수신 시
   대기 중인 probe 를 취소하고 예외를 위로 전파한다.
8. 심각도→신뢰도 내림차순으로 finding 정렬.
9. `ScanReport` 에 담아 반환.

이 파이프라인 덕분에 새 공격 모듈을 만들 때 하위 클래스가 구현해야 하는
훅은 **두 개뿐**이다: `_probes(target)`, `_build_finding(...)`.

## 새로운 공격 모듈 추가하기

`xss/` 패키지를 만든다고 가정.

```python
# xss/payloads.py
from dataclasses import dataclass
from common.result import Confidence

@dataclass(frozen=True)
class XSSPayload:
    value: str
    category: str
    signatures: tuple[bytes, ...]
    confidence: Confidence

PAYLOADS = (
    XSSPayload(
        value="<script>alert(1)</script>",
        category="reflected-script",
        signatures=(b"<script>alert(1)</script>",),
        confidence=Confidence.HIGH,
    ),
)
```

```python
# xss/module.py
from typing import Any, Iterable
from common.base import AttackModule, Probe
from common.http import HttpResponse
from common.result import Finding, Severity
from common.target import Target
from xss.payloads import PAYLOADS

class XSSModule(AttackModule):
    name = "xss"

    def _probes(self, target: Target) -> Iterable[Probe]:
        for parameter in self._candidate_params(target):
            for payload in PAYLOADS:
                yield Probe(
                    parameter=parameter,
                    payload_value=payload.value,
                    category=payload.category,
                    signatures=payload.signatures,
                    confidence=payload.confidence,
                    severity_when_signed=Severity.HIGH,
                )

    def _build_finding(self, target, probe, signature_hit, request_kwargs, response):
        return Finding(
            module=self.name,
            severity=probe.severity_when_signed,
            confidence=probe.confidence,
            title=f"Reflected XSS via {probe.parameter}: {probe.category}",
            target_url=target.url,
            method=target.method,
            parameter=probe.parameter,
            payload=probe.payload_value,
            evidence=signature_hit.decode("latin-1", errors="replace"),
            request={"url": request_kwargs["url"], "method": request_kwargs["method"]},
            response={"status": response.status_code, "length": len(response.body)},
        )
```

```python
# xss/__init__.py
from xss.module import XSSModule
from xss.payloads import PAYLOADS, XSSPayload
__all__ = ("XSSModule", "XSSPayload", "PAYLOADS")
```

마지막으로 워크스페이스 `pyproject.toml` 의 `[tool.setuptools] packages` 에
`"xss"` 를 추가하면 `XSSModule.run_json(...)` 까지 그대로 사용 가능하다.

## HttpClient — HTTP 클라이언트 래퍼

`requests.Session` 을 한 번 만들어 모든 워커가 공유한다. 풀(`HTTPAdapter`) 이
스레드-안전을 보장한다. 보안 기본값은 다음과 같다.

| 설정 | 기본값 | 이유 |
|---|---|---|
| `allow_redirects` | False | 프로브가 다른 호스트로 튀어나가는 것 차단 |
| `verify` | True | TLS 검증 — 명시적으로 False 줄 때만 우회 |
| 본문 상한 | 64 KiB | 메모리 보호. 응답이 크면 잘라서 시그니처만 검사 |
| `timeout` | 10s | 워커 행 방지 |
| `scope_predicate` | None | 부모 DAST 가 화이트리스트를 강제하고 싶을 때 콜백 주입 |

전송 실패는 예외를 던지는 대신 `HttpResponse(error="…", status_code=0)` 으로
돌아온다. 워커 스레드가 예외를 전파해 스캔 전체가 중단되는 사고를 막기
위함이다.

## injector — 페이로드 주입기

```python
inject(target, "<payload>", "id") -> {
    "method": "GET", "url": "...", "params": {...}, "data": ..., "headers": ...
}
```

원본 `Target` 은 변경하지 않는다(매번 dict 복사). GET 은 `params`, POST 는
`data` 를 갈아끼운다. 양쪽이 섞여 있는 경우(POST 에 쿼리스트링도 있을 때)
원래 키는 모두 보존된다.

## detector — 응답 분석

```python
match(body: bytes, signatures: Iterable[bytes]) -> bytes | None
```

순서대로 검사해 처음 매칭된 시그니처를 반환한다. 빈 시그니처(`b""`)는 무시.
이진 응답(`/proc/self/environ` 처럼 `\x00` 포함)도 안전하게 처리된다.

`baseline_diff(baseline, candidate)` 는 시간/길이 델타를 계산하는 보조 함수.
현재 모듈에서는 사용하지 않으나, 시그니처 매칭이 어려운 블라인드 SSRF 등을
도입할 때 활용 가능.

## AuthenticationError — 인증 실패 예외

`common/exceptions.py` 에 정의. `_probe_one` 이 401/403 응답을 받으면 발생한다.

- **`run()`** 경로: 호출자에게 그대로 전파된다. 호출자가 직접 처리해야 한다.
- **`run_json()`** 경로: 내부에서 catch 해 아래 에러 JSON 으로 변환한다.

```json
{"error": "auth_required", "status_code": 401}
```

`run_json()` 은 잘못된 요청 형식(`ValueError` / `TypeError`)도 에러 JSON 으로
변환해 반환한다.

```json
{"error": "invalid_request", "status_code": 0}
```

## JSON 계약 — `common/io.py`

부모 DAST 와의 통신 규약. 자세한 예시는 워크스페이스 루트 `README.md` 참고.

요약:

```
요청 (parent → module)            응답 (module → parent)
{                                  {
  "target":  {... Target ...},       "module":      "ssrf",
  "options": {                       "target_url":  "...",
    "max_workers":  8,               "started_at":  "ISO-8601 UTC",
    "payload_limit": null,           "finished_at": "ISO-8601 UTC",
    "timeout":   10.0,               "stats":    {"requests","errors","elapsed_ms"},
    "verify":    true,               "findings": [{... Finding ...}]
    ...                            }
  }
}
```

오류 응답 (`dump_error` 로 직렬화):

```
{"error": "<error_code>", "status_code": <int>}
```

`load_request(...)` 는 알 수 없는 키를 거부해 계약 표류를 조기에 잡고,
JSON 의 `null` 은 "값 미지정"으로 해석해 모듈 디폴트로 떨어지게 한다.

## 테스트

`tests/` 는 인젝터·디텍터·JSON I/O 의 순수 로직을 검증한다. 실제 HTTP
왕복은 워크스페이스 루트 `conftest.py` 의 `fixture_server` 를 쓰는 각
공격 모듈 테스트에서 검증된다.
