from .models import (
    ScanInput,
    ScanOutput,
    TechniqueQueries,
    ProbeLog,
    Parameter,
    ParamLocation,
    NmapDBInfo,
    DBMSType,
    Confidence,
    Endpoint,
)
from .scanner import run_scan

__all__ = [
    "run_scan",
    "ScanInput",
    "ScanOutput",
    "TechniqueQueries",
    "ProbeLog",
    "Parameter",
    "ParamLocation",
    "NmapDBInfo",
    "DBMSType",
    "Confidence",
    "Endpoint",
]


# ──────────────────────────────────────────────────────────────
# [Login 모듈 연동]
# ──────────────────────────────────────────────────────────────
# from sql_injection import run_scan, ScanInput
#
# 1. 로그인 완료 후 to_cookie_header(auth_result.cookies) 결과를
#    auth = {"cookie": "..."} 형태로 ScanInput 에 전달한다.
#
# 2. ScanOutput.auth_expired=True 수신 시 세션을 갱신하고
#    새 쿠키로 auth 를 재구성해 run_scan() 을 재호출한다.
# ──────────────────────────────────────────────────────────────


# ──────────────────────────────────────────────────────────────
# [Core 연동]
# ──────────────────────────────────────────────────────────────
# from sql_injection import run_scan, ScanInput
#
# scan_input = ScanInput.from_dict({...})
# sqli_result = asyncio.run(run_scan(scan_input))
# mid_core.get_sqli_data(sqli_result.to_dict())
# ──────────────────────────────────────────────────────────────
