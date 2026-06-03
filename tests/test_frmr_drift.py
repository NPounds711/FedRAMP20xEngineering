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


def test_draft_mapping_edits_applies_rename_only(tmp_path):
    a = tmp_path / "slice-a"; a.mkdir()
    (a / "mapping.yaml").write_text("capability: slice-a\nksis:\n  - id: KSI-IAM-01\n    obligation: required\n")
    c = tmp_path / "slice-c"; c.mkdir()
    (c / "mapping.yaml").write_text("capability: slice-c\nksis:\n  - id: KSI-IAM-OLD\n    obligation: required\n")
    diff = frmr_drift.diff_ksis(frmr_drift.extract_ksis(OLD), frmr_drift.extract_ksis(NEW))
    aff = frmr_drift.affected(diff, frmr_drift.load_slice_ksis(tmp_path))

    edits = frmr_drift.draft_mapping_edits(aff, tmp_path, apply=True)

    assert edits == [{"path": str(a / "mapping.yaml"), "old": "KSI-IAM-01", "new": "KSI-IAM-MFA"}]
    assert "KSI-IAM-MFA" in (a / "mapping.yaml").read_text()   # rename applied
    assert "KSI-IAM-OLD" in (c / "mapping.yaml").read_text()   # removal NOT auto-edited


def test_summarize_separates_auto_and_manual():
    diff = frmr_drift.diff_ksis(frmr_drift.extract_ksis(OLD), frmr_drift.extract_ksis(NEW))
    aff = [
        {"slice": "iam-mfa", "ksi": "KSI-IAM-01", "change": "renamed", "detail": "KSI-IAM-MFA", "auto_fixable": True},
        {"slice": "iam-mfa", "ksi": "KSI-IAM-OLD", "change": "removed", "detail": "", "auto_fixable": False},
    ]
    body = frmr_drift.summarize(diff, aff)
    assert "Auto-drafted" in body and "KSI-IAM-01` → `KSI-IAM-MFA" in body
    assert "Needs your decision" in body and "removed" in body


def test_run_reports_changed_and_summary(tmp_path):
    catalog = tmp_path / "catalog" / "FRMR.documentation.json"
    catalog.parent.mkdir(parents=True)
    catalog.write_text(json.dumps(OLD))
    slices = tmp_path / "slices"; (slices / "iam-mfa").mkdir(parents=True)
    (slices / "iam-mfa" / "mapping.yaml").write_text("capability: iam-mfa\nksis:\n  - id: KSI-IAM-01\n    obligation: required\n")

    result = frmr_drift.run(str(catalog), str(slices), NEW)

    assert result["changed"] is True
    assert any(a["change"] == "renamed" for a in result["affected"])
    assert "FRMR auto-sync" in result["summary"]


def test_run_no_change(tmp_path):
    catalog = tmp_path / "FRMR.documentation.json"
    catalog.write_text(json.dumps(NEW))
    slices = tmp_path / "slices"; slices.mkdir()
    result = frmr_drift.run(str(catalog), str(slices), NEW)
    assert result["changed"] is False


def test_main_apply_writes_catalog_and_summary(tmp_path):
    catalog = tmp_path / "catalog" / "FRMR.documentation.json"
    catalog.parent.mkdir(parents=True)
    catalog.write_text(json.dumps(OLD))
    slices = tmp_path / "slices"; (slices / "iam-mfa").mkdir(parents=True)
    (slices / "iam-mfa" / "mapping.yaml").write_text("capability: iam-mfa\nksis:\n  - id: KSI-IAM-01\n    obligation: required\n")
    new_path = tmp_path / "new.json"; new_path.write_text(json.dumps(NEW))
    summary = tmp_path / "summary.md"
    gh_out = tmp_path / "gh_out"

    rc = frmr_drift.main([
        "--catalog", str(catalog), "--slices", str(slices),
        "--offline-doc", str(new_path), "--summary-out", str(summary),
        "--github-output", str(gh_out), "--apply",
    ])

    assert rc == 0
    assert json.loads(catalog.read_text())["info"]["version"] == "new"
    assert "KSI-IAM-MFA" in (slices / "iam-mfa" / "mapping.yaml").read_text()
    assert "FRMR auto-sync" in summary.read_text()
    assert "changed=true" in gh_out.read_text()
