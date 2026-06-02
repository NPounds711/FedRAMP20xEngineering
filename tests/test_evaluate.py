from pathlib import Path

import pytest

from engine.evaluate import evaluate, opa_available

FIX = Path(__file__).resolve().parent / "fixtures" / "slice_ok"

pytestmark = pytest.mark.skipif(not opa_available(), reason="opa binary not installed")


def test_evaluate_pass():
    out = evaluate(FIX / "policy", "fr20x.fixture", {"enabled": True})
    assert out == {"result": "pass", "violations": []}


def test_evaluate_fail_collects_violations():
    out = evaluate(FIX / "policy", "fr20x.fixture", {"enabled": False})
    assert out["result"] == "fail"
    assert "fixture resource not enabled" in out["violations"]
