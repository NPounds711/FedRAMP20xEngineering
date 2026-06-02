from pathlib import Path

import pytest

from engine.collect import collect

FIX = Path(__file__).resolve().parent / "fixtures" / "slice_ok"


def test_collect_runs_provider_module():
    out = collect(FIX, "fixture", {"enabled": True})
    assert out == {"enabled": True, "resource_id": "fixture-1"}


def test_collect_missing_provider_raises():
    with pytest.raises(FileNotFoundError):
        collect(FIX, "nope", {})
