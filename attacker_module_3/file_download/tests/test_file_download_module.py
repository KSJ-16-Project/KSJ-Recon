"""FileDownloadModule 통합 테스트."""
import json

from common import HttpClient, Target
from file_download import FileDownloadModule


def test_finds_etc_passwd_via_get(fixture_server):
    target = Target(
        url=f"{fixture_server}/download",
        method="GET",
        params={"id": "1"},
        inject_params=["id"],
    )
    findings = FileDownloadModule(http=HttpClient(timeout=5.0), max_workers=4).run(target)
    passwd = [f for f in findings if "nix-passwd" in f.title]
    assert passwd, "expected an /etc/passwd finding"
    assert passwd[0].severity.value == "critical"
    assert passwd[0].confidence.value == "high"


def test_finds_passwd_via_post(fixture_server):
    target = Target(
        url=f"{fixture_server}/file",
        method="POST",
        data={"id": "1", "token": "demo"},
        inject_params=["id"],
    )
    findings = FileDownloadModule(http=HttpClient(timeout=5.0), max_workers=4).run(target)
    assert any(f.parameter == "id" and f.method == "POST" for f in findings)


def test_finds_windows_win_ini(fixture_server):
    # Windows 대상 — `..\windows\win.ini` 백슬래시 traversal 또는 절대 경로
    target = Target(
        url=f"{fixture_server}/download",
        method="GET",
        params={"id": "1"},
        inject_params=["id"],
    )
    findings = FileDownloadModule(http=HttpClient(timeout=5.0), max_workers=4).run(target)
    win = [f for f in findings if "windows-win-ini" in f.title]
    assert win, "expected a Windows win.ini finding"
    assert win[0].severity.value == "critical"


def test_finds_proc_environ_when_etc_blocked(fixture_server):
    # /etc 가 차단된 경우의 우회 경로 — /proc/self/environ
    target = Target(
        url=f"{fixture_server}/download",
        method="GET",
        params={"id": "1"},
        inject_params=["id"],
    )
    findings = FileDownloadModule(http=HttpClient(timeout=5.0), max_workers=4).run(target)
    proc = [f for f in findings if "nix-proc-environ" in f.title]
    assert proc, "expected a /proc/self/environ finding"
    # 시그니처가 다소 일반적이라 신뢰도는 MEDIUM 이지만 심각도는 CRITICAL
    assert proc[0].severity.value == "critical"
    assert proc[0].confidence.value == "medium"


def test_run_json_round_trip(fixture_server):
    request = json.dumps({
        "target": {
            "url": f"{fixture_server}/file",
            "method": "POST",
            "data": {"id": "1", "token": "demo"},
            "inject_params": ["id"],
        },
        "options": {"max_workers": 4, "timeout": 5.0},
    })
    response = FileDownloadModule.run_json(request)
    rpt = json.loads(response)
    assert rpt["module"] == "file_download"
    assert rpt["target_url"].endswith("/file")
    assert rpt["stats"]["requests"] >= 1
    assert any(f["title"].startswith("Path traversal via id:")
               for f in rpt["findings"])
    # 모든 finding 의 심각도는 CRITICAL
    assert all(f["severity"] == "critical" for f in rpt["findings"])


def test_no_findings_when_no_inject_params(fixture_server):
    target = Target(
        url=f"{fixture_server}/healthz",
        method="GET",
        params={},
        inject_params=[],
    )
    findings = FileDownloadModule(http=HttpClient(timeout=5.0)).run(target)
    assert findings == []
