import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class DBMSType(str, Enum):
    MYSQL = "MySQL"
    POSTGRESQL = "PostgreSQL"
    MSSQL = "MSSQL"
    ORACLE = "Oracle"
    SQLITE = "SQLite"
    UNKNOWN = "Unknown"


class ParamLocation(str, Enum):
    QUERY = "query"
    BODY = "body"
    COOKIE = "cookie"
    HEADER = "header"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Parameter:
    name: str
    location: ParamLocation
    value: str = ""


@dataclass
class NmapDBInfo:
    port: int
    service: str
    version: Optional[str] = None


@dataclass
class Endpoint:
    """한 번의 요청에 같이 보내야 할 파라미터 묶음."""
    url: str
    method: str = "GET"          # "GET" | "POST"
    enctype: str = ""            # "" | "application/x-www-form-urlencoded" | "multipart/form-data" | "application/json"
    params: list[Parameter] = field(default_factory=list)


@dataclass
class ScanInput:
    target_url: str
    endpoints: list[Endpoint] = field(default_factory=list)
    auth: dict[str, str] = field(default_factory=dict)
    nmap_data: Optional[NmapDBInfo] = None

    @classmethod
    def from_dict(cls, data: dict) -> "ScanInput":
        """전처리 LLM이 생성한 JSON dict를 ScanInput으로 변환한다."""
        nmap_raw = data.get("nmap_data")
        return cls(
            target_url=data["target_url"],
            endpoints=[
                Endpoint(
                    url=e["url"],
                    method=str(e.get("method", "GET")).upper(),
                    enctype=e.get("enctype", ""),
                    params=[
                        Parameter(
                            name=p["name"],
                            location=ParamLocation(p["location"]),
                            value=str(p.get("value", "")),
                        )
                        for p in e.get("params", [])
                        if p.get("location") in {"query", "body", "cookie", "header"}
                    ],
                )
                for e in data.get("endpoints", [])
            ],
            auth={k: v for k, v in (data.get("auth") or {}).items() if v},
            nmap_data=(
                NmapDBInfo(
                    port=int(nmap_raw["port"]),
                    service=nmap_raw["service"],
                    version=nmap_raw.get("version") or None,
                )
                if nmap_raw and (int(nmap_raw.get("port") or 0) or nmap_raw.get("service") or nmap_raw.get("version"))
                else None
            ),
        )


@dataclass
class ProbeLog:
    param: str
    payload: str
    response_status: int
    response_length: int
    matched_pattern: Optional[str] = None
    elapsed_ms: Optional[float] = None
    auth_expired: bool = False


@dataclass
class TechniqueQueries:
    confirmed: dict[str, list[str]]  # 프로빙에서 실제 반응한 기법 + 쿼리
    possible: dict[str, list[str]]   # 환경 조건상 가능한 기법 + 대표 쿼리


@dataclass
class ScanOutput:
    dbms_type: DBMSType
    dbms_version: Optional[str]
    confidence: Confidence
    injectable_params: list[dict]  # [{"param": str, "values": list[str], "url": str, "method": str}]
    technique_queries: TechniqueQueries
    probe_log: list[ProbeLog]
    auth_expired: bool = False  # True면 오케스트레이터가 Login 모듈 재호출

    def to_dict(self) -> dict:
        """결과를 JSON 직렬화가 가능한 딕셔너리로 변환합니다."""
        result_dict = asdict(self)
        result_dict["dbms_type"] = self.dbms_type.value
        result_dict["confidence"] = self.confidence.value
        del result_dict["probe_log"]
        return result_dict

    def to_json(self) -> str:
        """최종 LLM에게 전달할 JSON 문자열을 생성합니다."""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)
