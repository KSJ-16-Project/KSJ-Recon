"""디텍터 단위 테스트."""
from common.detector import baseline_diff, match
from common.http import HttpResponse


def test_match_returns_first_signature():
    assert match(b"AAA root:x:0:0 BBB", (b"alpha", b"root:x:0:0")) == b"root:x:0:0"


def test_match_none_when_no_signature():
    assert match(b"hello", (b"world",)) is None


def test_match_empty_signature_ignored():
    assert match(b"abc", (b"", b"x")) is None


def test_match_works_on_binary_body():
    body = b"\x00\x01PATH=/usr/bin\x00"
    assert match(body, (b"PATH=",)) == b"PATH="


def test_baseline_diff_computes_deltas():
    base = HttpResponse(status_code=200, body=b"x" * 100, elapsed_ms=10.0)
    cand = HttpResponse(status_code=500, body=b"x" * 250, elapsed_ms=15.0)
    d = baseline_diff(base, cand)
    assert d["status_changed"] is True
    assert d["length_delta"] == 150
    assert d["elapsed_delta_ms"] == 5.0


def test_baseline_diff_zero_when_identical():
    r = HttpResponse(status_code=200, body=b"x" * 10, elapsed_ms=7.0)
    d = baseline_diff(r, r)
    assert d["status_changed"] is False
    assert d["length_delta"] == 0
    assert d["elapsed_delta_ms"] == 0.0
