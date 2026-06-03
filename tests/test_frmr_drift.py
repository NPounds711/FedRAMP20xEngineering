import json
from pathlib import Path

from tools import frmr_drift

FIX = Path(__file__).resolve().parent / "fixtures" / "frmr"
OLD = json.loads((FIX / "doc_old.json").read_text())
NEW = json.loads((FIX / "doc_new.json").read_text())


def test_extract_ksis_flattens_indicators():
    out = frmr_drift.extract_ksis(NEW)
    assert set(out) == {"KSI-IAM-MFA", "KSI-IAM-NEW", "KSI-CNA-RNT"}
    mfa = out["KSI-IAM-MFA"]
    assert mfa["family"] == "IAM"
    assert mfa["fka"] == "KSI-IAM-01"
    assert mfa["controls"] == ["ia-2", "ia-2.1"]
    assert "phishing-resistant" in mfa["statement"]
    assert out["KSI-IAM-NEW"]["fka"] is None
    assert frmr_drift.extract_ksis({}) == {}


def test_diff_ksis_categorizes_every_change():
    d = frmr_drift.diff_ksis(frmr_drift.extract_ksis(OLD), frmr_drift.extract_ksis(NEW))
    assert d["renamed"] == [{"old": "KSI-IAM-01", "new": "KSI-IAM-MFA"}]
    assert d["added"] == ["KSI-IAM-NEW"]            # the rename target is NOT "added"
    assert d["removed"] == ["KSI-IAM-OLD"]          # the rename source is NOT "removed"
    assert d["restated"] == ["KSI-CNA-RNT"]
    assert d["controls_changed"] == ["KSI-CNA-RNT"]


def test_diff_ksis_no_change_is_empty():
    same = frmr_drift.extract_ksis(NEW)
    d = frmr_drift.diff_ksis(same, same)
    assert all(d[k] == [] for k in d)


def test_load_slice_ksis_reads_real_mappings():
    root = Path(__file__).resolve().parent.parent
    m = frmr_drift.load_slice_ksis(root / "slices")
    assert "network-restriction" in m.get("KSI-CNA-RNT", [])
    assert "iam-mfa" in m.get("KSI-IAM-MFA", [])


def test_affected_classifies_by_change(tmp_path):
    for name, ksi in [("slice-a", "KSI-IAM-01"), ("slice-b", "KSI-CNA-RNT"), ("slice-c", "KSI-IAM-OLD")]:
        d = tmp_path / name
        d.mkdir()
        (d / "mapping.yaml").write_text(f"capability: {name}\nksis:\n  - id: {ksi}\n    obligation: required\n")
    diff = frmr_drift.diff_ksis(frmr_drift.extract_ksis(OLD), frmr_drift.extract_ksis(NEW))
    items = frmr_drift.affected(diff, frmr_drift.load_slice_ksis(tmp_path))
    by_slice = {i["slice"]: i for i in items}
    assert by_slice["slice-a"]["change"] == "renamed" and by_slice["slice-a"]["auto_fixable"] is True
    assert by_slice["slice-a"]["detail"] == "KSI-IAM-MFA"
    assert by_slice["slice-c"]["change"] == "removed" and by_slice["slice-c"]["auto_fixable"] is False
    assert all(i["auto_fixable"] is False for i in items if i["slice"] == "slice-b")
