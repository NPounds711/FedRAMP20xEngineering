import json
from pathlib import Path

import pytest

from engine.cli import main
from engine.evaluate import opa_available

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_SLICE = ROOT / "slices" / "_fixture"


def test_render_and_report_subcommands(tmp_path, capsys):
    det = {
        "capability": "fixture", "title": "Fixture Capability", "result": "pass",
        "violations": [], "evidence_ref": "b" * 64, "collected_at": "2026-06-02T00:00:00Z",
        "frameworks": {"fedramp-20x": [{"ksi": "KSI-A", "obligation": "required"}],
                       "nist-800-53-rev5": ["ac-1"]},
    }
    det_path = tmp_path / "dets.json"
    det_path.write_text(json.dumps([det]))

    assert main(["render", str(det_path), "--format", "human"]) == 0
    assert "Fixture Capability" in capsys.readouterr().out

    idx = tmp_path / "idx.csv"
    idx.write_text("KSI_ID,Obligation\nKSI-A,required\nKSI-B,required\n")
    assert main(["report", str(idx), str(det_path)]) == 0
    assert json.loads(capsys.readouterr().out)["required_addressed"] == "1/2"


@pytest.mark.skipif(not opa_available(), reason="opa binary not installed")
def test_run_slice_end_to_end(tmp_path, capsys):
    rc = main([
        "run-slice", str(FIXTURE_SLICE), "--provider", "fixture",
        "--run-id", "demo-1", "--evidence-dir", str(tmp_path / "evidence"),
    ])
    assert rc == 0
    det = json.loads(capsys.readouterr().out)
    assert det["result"] == "pass"
    assert det["frameworks"]["nist-800-53-rev5"] == ["ac-1"]
    assert main(["verify", "fixture", "--evidence-dir", str(tmp_path / "evidence")]) == 0
