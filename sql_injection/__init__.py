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
]


# ──────────────────────────────────────────────────────────────
# [Core 연동 가이드]
# ──────────────────────────────────────────────────────────────
#
# ■ 시작 함수
#   run_scan(scan_input: ScanInput) → ScanOutput        # async
#   └─ scanner.py 에 구현, 이 __init__.py 에서 export
#
# ■ Core 호출 순서 (entry_core.py 기준)
#   1. ScanInput.from_dict(d)        입력 객체 생성
#   2. asyncio.run(run_scan(...))    SQLi 탐지 실행
#   3. ScanOutput.to_dict()          결과 직렬화 → middle_core 에 전달
#
# ■ ScanInput.from_dict() 에 넘길 딕셔너리 구조
#   {
#     "target_url":   "https://example.com/page",
#     "crawler_data": [                               # crawler 폼 파라미터 변환 필요
#         {"name": "id",   "location": "query", "value": "86"},
#         {"name": "user", "location": "body",  "value": ""}
#     ],
#     "auth": {                                       # AuthResult.cookies → 문자열 변환 필요
#         "cookie": "session=abc; csrftoken=xyz"      # key=val; key2=val2 형식
#     },
#     "nmap_data":  {"port": 3306, "service": "mysql", "version": ""},
#     "fuzzer_data": ["https://example.com/hidden"]   # URL 문자열 리스트
#   }
#
# ■ crawler 데이터 변환 예시 (CrawlResult → crawler_data)
#   crawler_data = []
#   for page in crawl_data.public_pages + crawl_data.authenticated_pages:
#       for form in page.forms:
#           loc = "body" if form.method == "POST" else "query"
#           for f in form.fields:
#               if f.name:
#                   crawler_data.append({"name": f.name, "location": loc, "value": ""})
#
# ■ auth 변환 예시 (AuthResult.cookies → cookie 문자열)
#   auth = {}
#   if crawl_data.auth and crawl_data.auth.cookies:
#       auth["cookie"] = "; ".join(f"{c['name']}={c['value']}" for c in crawl_data.auth.cookies)
#
# ■ ScanOutput 구조 (to_dict() 결과 → middle_core["sqli"] 에 저장)
#   {
#     "dbms_type":         "MSSQL",
#     "dbms_version":      "2012",
#     "confidence":        "high",
#     "injectable_params": ["frmSearchWord"],
#     "technique_queries": {
#         "confirmed": {"Error-based": ["'", "' OR sqlspider"]},
#         "possible":  {"Union-based": [...], "Stacked queries": [...]}
#     },
#     "probe_log":    [...],
#     "auth_expired": false
#   }
#
# ■ auth_expired 처리 (entry_core.py 오케스트레이터 책임)
#   sqli_result = asyncio.run(run_scan(scan_input))
#   if sqli_result.auth_expired:
#       # Login 모듈 재호출 → 새 auth dict → run_scan 재시도 (최대 3회)
#       pass
#
# ■ middle_core.py 에 추가 필요한 항목
#   storage["sqli"] = None
#   def get_sqli_data(self, sqli_data): self.storage["sqli"] = sqli_data
#
# ■ ksj_llm.py build_prompt() 에 추가 필요한 항목
#   if scan_data.get("sqli"):
#       sections.append("[SQL Injection 탐지 결과]\n"
#                       + json.dumps(scan_data["sqli"], indent=2, ensure_ascii=False))
# ──────────────────────────────────────────────────────────────
