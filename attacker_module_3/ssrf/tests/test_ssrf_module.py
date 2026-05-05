"""SSRFModule 통합 테스트 — 인-프로세스 HTTP 픽스처 사용."""
import json
import socket

from common import HttpClient, Target
from ssrf import SSRFModule


def _closed_loopback_port() -> int:
    # 즉시 RST 가 떨어지는 닫힌 포트를 잡아 전송 실패 경로를 자극한다
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_ssrf_finds_file_etc_passwd_via_get(fixture_server):
    target = Target(
        url=f"{fixture_server}/proxy",
        method="GET",
        params={"url": "https://placeholder.local"},
        inject_params=["url"],
    )
    findings = SSRFModule(http=HttpClient(timeout=5.0), max_workers=4).run(target)
    nix = [f for f in findings if "scheme-file-nix" in f.title]
    assert nix, "expected a file:///etc/passwd finding"
    assert nix[0].severity.value == "critical"
    assert nix[0].confidence.value == "high"
    assert nix[0].method == "GET"
    assert nix[0].parameter == "url"


def test_ssrf_finds_file_windows_win_ini(fixture_server):
    target = Target(
        url=f"{fixture_server}/proxy",
        method="GET",
        params={"url": "https://placeholder.local"},
        inject_params=["url"],
    )
    findings = SSRFModule(http=HttpClient(timeout=5.0), max_workers=4).run(target)
    win = [f for f in findings if "scheme-file-windows" in f.title]
    assert win, "expected a file:///c:/windows/win.ini finding"
    assert win[0].severity.value == "critical"


def test_ssrf_finds_via_post(fixture_server):
    target = Target(
        url=f"{fixture_server}/proxy",
        method="POST",
        data={"target": "https://placeholder.local", "token": "demo"},
        inject_params=["target"],
    )
    findings = SSRFModule(http=HttpClient(timeout=5.0), max_workers=4).run(target)
    assert any(f.parameter == "target" and f.method == "POST" for f in findings)


def test_ssrf_run_json_round_trip(fixture_server):
    request = json.dumps({
        "target": {
            "url": f"{fixture_server}/proxy",
            "method": "POST",
            "data": {"target": "https://placeholder.local", "token": "demo"},
            "inject_params": ["target"],
        },
        "options": {"max_workers": 4, "timeout": 5.0},
    })
    response = SSRFModule.run_json(request)
    rpt = json.loads(response)
    assert rpt["module"] == "ssrf"
    assert rpt["target_url"].endswith("/proxy")
    assert rpt["stats"]["requests"] >= 1
    assert any(f["title"].startswith("SSRF via target:") for f in rpt["findings"])
    # 가장 위험한 항목은 정렬 결과 첫 번째에 있어야 한다
    assert rpt["findings"][0]["severity"] == "critical"


def test_ssrf_no_findings_when_no_inject_params(fixture_server):
    target = Target(
        url=f"{fixture_server}/healthz",
        method="GET",
        params={},
        inject_params=[],
    )
    findings = SSRFModule(http=HttpClient(timeout=5.0)).run(target)
    assert findings == []


def test_ssrf_payload_limit_caps_probes(fixture_server):
    response = SSRFModule.run_json(json.dumps({
        "target": {
            "url": f"{fixture_server}/proxy",
            "method": "GET",
            "params": {"url": "x"},
            "inject_params": ["url"],
        },
        "options": {"max_workers": 2, "payload_limit": 1, "timeout": 5.0},
    }))
    rpt = json.loads(response)
    assert rpt["stats"]["requests"] == 1


def test_ssrf_handles_transport_errors_gracefully():
    port = _closed_loopback_port()
    target = Target(
        url=f"http://127.0.0.1:{port}/proxy",
        method="GET",
        params={"url": "x"},
        inject_params=["url"],
    )
    findings = SSRFModule(
        http=HttpClient(timeout=1.0),
        max_workers=2,
        payload_limit=2,
    ).run(target)
    assert findings == []
