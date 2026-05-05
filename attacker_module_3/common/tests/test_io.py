"""JSON I/O 계약 테스트 — 요청 파싱, 응답 직렬화, 라운드트립."""
import json

import pytest

from common.io import dump_report, load_request
from common.result import Confidence, Finding, ScanReport, Severity


def test_load_request_parses_minimal_get():
    raw = json.dumps({
        "target": {
            "url": "http://x/y",
            "method": "GET",
            "params": {"id": "1"},
            "inject_params": ["id"],
        },
    })
    req = load_request(raw)
    assert req.target.url == "http://x/y"
    assert req.target.method == "GET"
    assert req.target.params == {"id": "1"}
    assert req.target.inject_params == ["id"]
    assert req.http_kwargs == {}
    assert req.module_kwargs == {}


def test_load_request_treats_null_options_as_defaults():
    # 부모 DAST 가 옵션 값을 null 로 채워 보내도 디폴트로 떨어져야 한다 —
    # 그렇지 않으면 모듈 생성자에서 int(None) 등으로 깨진다.
    req = load_request({
        "target": {"url": "http://x", "method": "GET",
                   "params": {"id": "1"}, "inject_params": ["id"]},
        "options": {
            "max_workers": None, "payload_limit": None,
            "timeout": None, "verify": None, "user_agent": None,
            "proxies": None, "allow_redirects": None,
        },
    })
    assert req.http_kwargs == {}
    assert req.module_kwargs == {}


def test_load_request_separates_http_and_module_options():
    req = load_request({
        "target": {
            "url": "http://x", "method": "POST",
            "data": {"k": "v"}, "inject_params": ["k"],
        },
        "options": {
            "max_workers": 4, "payload_limit": 10,
            "timeout": 5.0, "verify": False, "user_agent": "T/1",
            "proxies": {"http": "http://127.0.0.1:8080"},
            "allow_redirects": False,
        },
    })
    assert req.module_kwargs == {"max_workers": 4, "payload_limit": 10}
    assert req.http_kwargs == {
        "timeout": 5.0,
        "verify": False,
        "user_agent": "T/1",
        "proxies": {"http": "http://127.0.0.1:8080"},
        "allow_redirects": False,
    }


def test_load_request_accepts_dict_directly():
    req = load_request({"target": {"url": "http://x", "method": "GET"}})
    assert req.target.url == "http://x"


def test_load_request_rejects_unknown_top_level_keys():
    with pytest.raises(ValueError):
        load_request({"target": {"url": "http://x"}, "extra": True})


def test_load_request_rejects_unknown_option_keys():
    with pytest.raises(ValueError):
        load_request({"target": {"url": "http://x"}, "options": {"foo": 1}})


def test_load_request_rejects_unknown_target_keys():
    with pytest.raises(ValueError):
        load_request({"target": {"url": "http://x", "weird": True}})


def test_load_request_requires_url():
    with pytest.raises(ValueError):
        load_request({"target": {"method": "GET"}})


def test_dump_report_round_trip_preserves_values():
    f = Finding(
        module="ssrf",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        title="SSRF via url: metadata-aws",
        target_url="http://x",
        method="GET",
        parameter="url",
        payload="http://169.254.169.254/latest/meta-data/",
        evidence="ami-id",
        request={"url": "http://x", "method": "GET"},
        response={"status": 200, "elapsed_ms": 1.0, "length": 10},
    )
    rpt = ScanReport(
        module="ssrf",
        target_url="http://x",
        started_at="2026-05-01T00:00:00.000Z",
        finished_at="2026-05-01T00:00:00.100Z",
        findings=[f],
        stats={"requests": 1, "errors": 0, "elapsed_ms": 1.234},
    )
    parsed = json.loads(dump_report(rpt))
    assert parsed["module"] == "ssrf"
    assert parsed["findings"][0]["severity"] == "critical"
    assert parsed["findings"][0]["confidence"] == "high"
    assert parsed["findings"][0]["payload"].startswith("http://169.254")
    assert parsed["stats"] == {"requests": 1, "errors": 0, "elapsed_ms": 1.234}
