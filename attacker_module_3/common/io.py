"""JSON 입출력 계약 — 부모 DAST 와 어태커 모듈 간의 표준 페이로드 형식."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from attacker_module_3.common.result import ScanReport
from attacker_module_3.common.target import Target


_REQUEST_TOP_KEYS = frozenset({"target", "options"})
_OPTIONS_KEYS = frozenset({
    "max_workers", "payload_limit",
    "user_agent", "verify", "proxies",
    "allow_redirects", "timeout",
})

# HttpClient 가 받는 키와 모듈 생성자가 받는 키를 분리해 보관
_HTTP_OPTION_KEYS = ("user_agent", "verify", "proxies", "allow_redirects", "timeout")
_MODULE_OPTION_KEYS = ("max_workers", "payload_limit")


#JSON 요청을 파싱한 결과를 담는 객체
@dataclass
class ParsedRequest:
    target: Target
    http_kwargs: dict[str, Any] = field(default_factory=dict)
    module_kwargs: dict[str, Any] = field(default_factory=dict)


# JSON 요청을 파싱해 모듈 호출에 필요한 슬라이스로 분리하는 함수
def load_request(raw: str | bytes | bytearray | dict[str, Any]) -> ParsedRequest:
    """JSON 또는 dict 형태의 요청을 파싱해 모듈 호출에 필요한 슬라이스로 분리한다."""
    if isinstance(raw, (str, bytes, bytearray)):
        doc = json.loads(raw)
    elif isinstance(raw, dict):
        doc = raw
    else:
        raise TypeError(f"unsupported request type: {type(raw).__name__}")

    if not isinstance(doc, dict):
        raise ValueError("request must be a JSON object")

    # 요청에 허용되지 않는 키가 있으면 에러
    unknown = set(doc) - _REQUEST_TOP_KEYS
    if unknown:
        raise ValueError(f"unknown request keys: {sorted(unknown)}")

    if "target" not in doc:
        raise ValueError("request missing 'target'")
    target_doc = doc["target"]
    if not isinstance(target_doc, dict):
        raise ValueError("'target' must be an object")
    target = Target.from_dict(target_doc)

    options = doc.get("options") or {}
    if not isinstance(options, dict):
        raise ValueError("'options' must be an object")
    bad = set(options) - _OPTIONS_KEYS
    if bad:
        raise ValueError(f"unknown options: {sorted(bad)}")

    # JSON 의 null 처리 & None 값을 옵션에서 제외
    # int(None) / 헤더에 None 주입 같은 사고를 방지한다.
    http_kwargs = {
        k: options[k]
        for k in _HTTP_OPTION_KEYS
        if k in options and options[k] is not None
    }
    module_kwargs = {
        k: options[k]
        for k in _MODULE_OPTION_KEYS
        if k in options and options[k] is not None
    }
    return ParsedRequest(target=target, http_kwargs=http_kwargs, module_kwargs=module_kwargs)


def dump_error(error: str, status_code: int) -> str:
    """인증 실패 등 모듈 수준 오류를 JSON 문자열로 직렬화한다."""
    return json.dumps(
        {"error": error, "status_code": status_code},
        separators=(",", ":"),
    )


# ScanReport 객체를 JSON 문자열로 변환
def dump_report(report: ScanReport) -> str:
    """ScanReport 를 JSON 문자열로 직렬화한다.

    ensure_ascii=False 로 비-ASCII 페이로드/증거가 그대로 살아남게 하고,
    구분자는 콤팩트 모드로 — 부모 DAST 가 그대로 큐/파이프로 흘려보내기 좋게.
    """
    return json.dumps(
        report.to_dict(),
        ensure_ascii=False,
        separators=(",", ":"),
    )
