import json
from pathlib import Path

import pytest

from engine.cli import main
from engine.evaluate import opa_available

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_SLICE = ROOT / "slices" / "_fixture"


@pytest.mark.skipif(not opa_available(), reason="opa binary not installed")
def test_config_file_is_passed_to_collector(tmp_path, capsys):
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({"enabled": False}))
    rc = main([
        "run-slice", str(FIXTURE_SLICE), "--provider", "fixture",
        "--run-id", "cfg-1", "--evidence-dir", str(tmp_path / "ev"),
        "--config", str(cfg),
    ])
    assert rc == 0
    det = json.loads(capsys.readouterr().out)
    assert det["result"] == "fail"  # enabled=false => fixture policy violation


def test_missing_config_file_is_a_clean_error(tmp_path, capsys):
    rc = main([
        "run-slice", str(FIXTURE_SLICE), "--provider", "fixture",
        "--run-id", "x", "--evidence-dir", str(tmp_path / "ev"),
        "--config", str(tmp_path / "nope.json"),
    ])
    assert rc == 1
    assert "fr20x: error:" in capsys.readouterr().err
