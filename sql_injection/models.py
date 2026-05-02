from dataclasses import dataclass, field
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
class ScanInput:
    target_url: str
    crawler_data: list[Parameter]
    auth: dict[str, str] = field(default_factory=dict)   # Login 모듈이 채워서 넘겨줌
    nmap_data: Optional[NmapDBInfo] = None
    fuzzer_data: list[str] = field(default_factory=list) # Fuzzer가 발견한 숨겨진 엔드포인트 URL 목록


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
    injectable_params: list[str]
    technique_queries: TechniqueQueries
    probe_log: list[ProbeLog]
    auth_expired: bool = False  # True면 오케스트레이터가 Login 모듈 재호출
