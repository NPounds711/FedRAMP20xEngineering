from pathlib import Path

from engine.slice import load_mapping

SLICE = Path(__file__).resolve().parent.parent / "slices" / "iam-mfa"


def test_mapping_validates_and_targets_the_right_controls():
    m = load_mapping(SLICE)
    assert m["capability"] == "iam-mfa"
    assert m["rego_package"] == "fr20x.iam_mfa"
    assert {k["id"] for k in m["ksis"]} == {"KSI-IAM-MFA"}
    assert m["ksis"][0]["obligation"] == "required"
    assert set(m["nist_controls"]) == {"ia-2", "ia-2.1", "ia-2.2", "ia-2.8"}
    assert set(m["providers"]) == {"okta", "entra", "aws", "gcp"}
