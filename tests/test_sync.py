import json
from pathlib import Path

from tools.sync import diff_catalog, extract_obligations, sync

FIX = Path(__file__).resolve().parent / "fixtures"


def test_extract_obligations_maps_must_and_should():
    doc = json.loads((FIX / "frmr_old" / "FRMR.KSI.key-security-indicators.json").read_text())
    obs = extract_obligations(doc)
    assert obs["KSI-A"] == "required"
    assert obs["KSI-C"] == "recommended"


def test_diff_catalog_reports_added_removed_and_changed():
    old = json.loads((FIX / "frmr_old" / "FRMR.KSI.key-security-indicators.json").read_text())
    new = json.loads((FIX / "frmr_new" / "FRMR.KSI.key-security-indicators.json").read_text())
    d = diff_catalog(old, new)
    assert d["added"] == ["KSI-D"]
    assert d["removed"] == ["KSI-B"]
    assert d["obligation_changed"] == ["KSI-C"]


def test_sync_offline_copies_files(tmp_path):
    written = sync(tmp_path / "out", offline_dir=FIX / "frmr_old")
    assert "FRMR.KSI.key-security-indicators.json" in written
    assert (tmp_path / "out" / "FRMR.KSI.key-security-indicators.json").exists()
