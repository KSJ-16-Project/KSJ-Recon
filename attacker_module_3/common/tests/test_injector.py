"""인젝터 단위 테스트."""
import pytest

from common.injector import inject
from common.target import Target


def test_inject_get_replaces_param():
    t = Target(url="http://x/y", method="GET", params={"id": "1", "k": "v"})
    out = inject(t, "PAYLOAD", "id")
    assert out["method"] == "GET"
    assert out["url"] == "http://x/y"
    assert out["params"] == {"id": "PAYLOAD", "k": "v"}
    assert out["data"] is None


def test_inject_get_does_not_mutate_target():
    t = Target(url="http://x/y", method="GET", params={"id": "1"})
    inject(t, "P", "id")
    assert t.params == {"id": "1"}


def test_inject_post_replaces_data_and_keeps_query():
    t = Target(url="http://x/y", method="POST",
               data={"id": "1", "tok": "T"}, params={"q": "1"})
    out = inject(t, "P", "id")
    assert out["method"] == "POST"
    assert out["data"] == {"id": "P", "tok": "T"}
    assert out["params"] == {"q": "1"}


def test_inject_post_adds_param_if_missing():
    t = Target(url="http://x/y", method="POST", data={})
    out = inject(t, "P", "new")
    assert out["data"] == {"new": "P"}


def test_target_rejects_unsupported_method():
    with pytest.raises(ValueError):
        Target(url="http://x", method="PUT")  # type: ignore[arg-type]


def test_inject_unsupported_method_raises_at_call_time():
    t = Target(url="http://x", method="GET")
    # 검증을 우회해 잘못된 메서드 상태를 강제 — 인젝터 자체의 가드 동작 확인
    object.__setattr__(t, "method", "DELETE")
    with pytest.raises(ValueError):
        inject(t, "p", "id")
