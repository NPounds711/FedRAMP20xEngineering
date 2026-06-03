import importlib.util
from pathlib import Path

COLLECTOR = Path(__file__).resolve().parent.parent / "slices" / "iam-mfa" / "collectors" / "aws.py"


def _load():
    spec = importlib.util.spec_from_file_location("aws_collector", COLLECTOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_normalize_classifies_aws_devices():
    aws = _load()
    raw = {
        "policy": {"mfa_required": True, "phishing_resistant_required": True},
        "users": [
            {"id": "alice", "status": "ACTIVE", "type": "human", "factors": ["WebAuthn"]},
            {"id": "bob", "status": "ACTIVE", "type": "human", "factors": ["TOTP"]},
            {"id": "carol", "status": "ACTIVE", "type": "human", "factors": []},
        ],
    }
    out = aws.normalize(raw)
    assert out["users_evaluated"] == 3
    assert out["users_without_mfa"] == ["carol"]
    assert out["users_with_non_phishing_resistant_mfa"] == ["bob"]


def test_collect_uses_offline_raw_seam():
    aws = _load()
    out = aws.collect({"raw": {
        "policy": {"mfa_required": True, "phishing_resistant_required": True},
        "users": [{"id": "a", "status": "ACTIVE", "type": "human", "factors": ["WebAuthn"]}],
    }})
    assert out["users_without_mfa"] == []
