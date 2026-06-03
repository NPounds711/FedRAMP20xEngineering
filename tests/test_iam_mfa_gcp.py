import importlib.util
from pathlib import Path

COLLECTOR = Path(__file__).resolve().parent.parent / "slices" / "iam-mfa" / "collectors" / "gcp.py"


def _load():
    spec = importlib.util.spec_from_file_location("gcp_collector", COLLECTOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_normalize_classifies_google_2sv():
    gcp = _load()
    raw = {
        "policy": {"mfa_required": True, "phishing_resistant_required": True},
        "users": [
            {"id": "alice@x", "status": "ACTIVE", "type": "human", "factors": ["SECURITY_KEY"]},
            {"id": "bob@x", "status": "ACTIVE", "type": "human", "factors": ["GOOGLE_PROMPT"]},
            {"id": "carol@x", "status": "ACTIVE", "type": "human", "factors": []},
        ],
    }
    out = gcp.normalize(raw)
    assert out["users_evaluated"] == 3
    assert out["users_without_mfa"] == ["carol@x"]
    assert out["users_with_non_phishing_resistant_mfa"] == ["bob@x"]


def test_collect_uses_offline_raw_seam():
    gcp = _load()
    out = gcp.collect({"raw": {
        "policy": {"mfa_required": True, "phishing_resistant_required": True},
        "users": [{"id": "a@x", "status": "ACTIVE", "type": "human", "factors": ["SECURITY_KEY"]}],
    }})
    assert out["users_with_non_phishing_resistant_mfa"] == []
