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
