"""대상(Target) 표현 및 검증"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Literal


_ALLOWED_METHODS = ("GET", "POST")
_ALLOWED_FIELDS = frozenset({
    "url", "method", "params", "data", "headers", "inject_params", "timeout",
})


@dataclass
class Target:
    url: str
    method: Literal["GET", "POST"] = "GET"
    params: dict[str, str] | None = None
    data: dict[str, str] | None = None
    headers: dict[str, str] | None = None
    inject_params: list[str] = field(default_factory=list)
    timeout: float | None = None

    # 객체 생성 후 검증 및 정규화
    def __post_init__(self) -> None:
        # 메서드는 대소문자 정규화 후 화이트리스트만 허용한다
        m = (self.method or "GET").upper()
        if m not in _ALLOWED_METHODS:
            raise ValueError(f"unsupported method: {self.method!r}")
        self.method = m  # type: ignore[assignment]

    # 딕셔너리에서 Target 객체를 생성
    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Target":
        # 알 수 없는 키는 거부 — 계약 표류를 조기에 잡기 위함
        unknown = set(d) - _ALLOWED_FIELDS
        if unknown:
            raise ValueError(f"unknown target fields: {sorted(unknown)}")
        if "url" not in d:
            raise ValueError("target missing required field 'url'")
        return cls(
            url=d["url"],
            method=d.get("method", "GET"),
            params=d.get("params"),
            data=d.get("data"),
            headers=d.get("headers"),
            inject_params=list(d.get("inject_params") or []),
            timeout=d.get("timeout"),
        )

    # YAML 파일에서 Target 객체 목록을 읽어오기
    @classmethod
    def load_yaml(cls, path: str | os.PathLike[str]) -> list["Target"]:
        # PyYAML 임포트는 게으르게 — 코어 의존을 줄이기 위함
        import yaml  # type: ignore[import-untyped]
        with open(path, "rb") as fh:
            doc = yaml.safe_load(fh) or []
        if not isinstance(doc, list):
            raise ValueError(f"{path}: expected a YAML list at top level")
        return [cls.from_dict(item) for item in doc]
