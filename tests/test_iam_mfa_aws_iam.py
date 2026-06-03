import importlib.util
from pathlib import Path

COLLECTOR = Path(__file__).resolve().parent.parent / "slices" / "iam-mfa" / "collectors" / "aws-iam.py"


def _load():
    spec = importlib.util.spec_from_file_location("iam_aws_iam", COLLECTOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_normalize_classifies_classic_iam_mfa():
    aws = _load()
    raw = {
        "policy": {"mfa_required": True, "phishing_resistant_required": True},
        "users": [
            {"id": "alice", "status": "ACTIVE", "type": "human", "factors": ["fido"]},   # phishing-resistant
            {"id": "bob", "status": "ACTIVE", "type": "human", "factors": ["virtual"]},   # weak (TOTP)
            {"id": "carol", "status": "ACTIVE", "type": "human", "factors": []},          # NO MFA
        ],
    }
    out = aws.normalize(raw)
    assert out["subject_scope"] == "all-human-users"
    assert out["users_evaluated"] == 3
    assert out["users_without_mfa"] == ["carol"]
    assert out["users_with_non_phishing_resistant_mfa"] == ["bob"]


def test_factor_label_classifies_device_serials():
    aws = _load()
    assert aws._factor_label("arn:aws:iam::123456789012:u2f/MySecurityKey") == "fido"
    assert aws._factor_label("arn:aws:iam::123456789012:mfa/MyVirtualDevice") == "virtual"
    assert aws._factor_label("GAHT12345678") == "virtual"  # hardware OTP serial


def test_collect_uses_offline_raw_seam():
    aws = _load()
    out = aws.collect({"raw": {
        "policy": {"mfa_required": True, "phishing_resistant_required": True},
        "users": [{"id": "a", "status": "ACTIVE", "type": "human", "factors": ["fido"]}],
    }})
    assert out["users_without_mfa"] == []
    assert out["users_evaluated"] == 1
