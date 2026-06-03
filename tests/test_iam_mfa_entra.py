import importlib.util
from pathlib import Path

COLLECTOR = Path(__file__).resolve().parent.parent / "slices" / "iam-mfa" / "collectors" / "entra.py"


def _load():
    spec = importlib.util.spec_from_file_location("entra_collector", COLLECTOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_normalize_classifies_entra_methods():
    entra = _load()
    raw = {
        "policy": {"mfa_required": True, "phishing_resistant_required": False},
        "users": [
            {"id": "alice@x", "status": "ACTIVE", "type": "human", "factors": ["fido2"]},
            {"id": "bob@x", "status": "ACTIVE", "type": "human", "factors": ["microsoftAuthenticator"]},
            {"id": "dan@x", "status": "ACTIVE", "type": "human", "factors": []},
            {"id": "guest@x", "status": "ACTIVE", "type": "guest", "factors": []},
        ],
    }
    out = entra.normalize(raw)
    assert out["mfa_required_by_policy"] is True
    assert out["phishing_resistant_required_by_policy"] is False
    assert out["users_evaluated"] == 3                       # guest excluded
    assert out["users_without_mfa"] == ["dan@x"]
    assert out["users_with_non_phishing_resistant_mfa"] == ["bob@x"]


def test_collect_uses_offline_raw_seam():
    entra = _load()
    out = entra.collect({"raw": {
        "policy": {"mfa_required": True, "phishing_resistant_required": True},
        "users": [{"id": "a@x", "status": "ACTIVE", "type": "human", "factors": ["windowsHelloForBusiness"]}],
    }})
    assert out["users_with_non_phishing_resistant_mfa"] == []
