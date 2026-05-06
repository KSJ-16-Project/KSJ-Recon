"""파라미터 페이로드 주입기."""
from __future__ import annotations

from typing import Any

from common.target import Target


def inject(target: Target, payload: str, parameter: str) -> dict[str, Any]:
    """대상의 지정 파라미터에 페이로드를 주입한 뒤 HttpClient.request 인자를 돌려준다.

    GET 은 쿼리 파라미터, POST 는 본문 폼 데이터를 갈아끼운다. 양쪽 모두 원본
    Target 자체는 변경하지 않는다.
    """
    method = (target.method or "GET").upper()

    if method == "GET":
        params = dict(target.params or {})
        params[parameter] = payload
        return {
            "method": "GET",
            "url": target.url,
            "params": params,
            "data": None,
            "headers": dict(target.headers or {}),
            "timeout": target.timeout,
        }

    if method == "POST":
        data = dict(target.data or {})
        data[parameter] = payload
        return {
            "method": "POST",
            "url": target.url,
            "params": dict(target.params or {}),
            "data": data,
            "headers": dict(target.headers or {}),
            "timeout": target.timeout,
        }

    raise ValueError(f"unsupported method: {method!r}")
