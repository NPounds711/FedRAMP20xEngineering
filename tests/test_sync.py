import json
import urllib.error
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
    result = sync(tmp_path / "out", offline_dir=FIX / "frmr_old")
    assert "FRMR.KSI.key-security-indicators.json" in result["written"]
    assert (tmp_path / "out" / "FRMR.KSI.key-security-indicators.json").exists()
    assert result["failed"] == {}


def test_sync_online_records_fetch_failures_without_aborting(tmp_path, monkeypatch):
    import tools.sync as sync_mod

    def boom(url):
        raise urllib.error.URLError("boom")

    monkeypatch.setattr(sync_mod, "_fetch", boom)
    result = sync_mod.sync(tmp_path / "out")  # online mode (no offline_dir)
    assert result["written"] == {}
    assert len(result["failed"]) == len(sync_mod.FRMR_FILES)


def test_extract_obligations_skips_indicator_without_id():
    doc = {"FRMR": {"KSI": [{"indicators": [
        {"indicator": "MUST no id"},
        {"id": "KSI-Z", "indicator": "SHOULD y"},
    ]}]}}
    obs = extract_obligations(doc)
    assert obs == {"KSI-Z": "recommended"}
