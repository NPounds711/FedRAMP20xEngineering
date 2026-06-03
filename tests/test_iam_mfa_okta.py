import importlib.util
from pathlib import Path

COLLECTOR = Path(__file__).resolve().parent.parent / "slices" / "iam-mfa" / "collectors" / "okta.py"


def _load():
    spec = importlib.util.spec_from_file_location("okta_collector", COLLECTOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_normalize_classifies_factors_and_policy():
    okta = _load()
    raw = {
        "policy": {"mfa_required": True, "phishing_resistant_required": True},
        "users": [
            {"id": "alice@x", "status": "ACTIVE", "type": "human", "factors": ["webauthn"]},
            {"id": "bob@x", "status": "ACTIVE", "type": "human", "factors": []},
            {"id": "carol@x", "status": "ACTIVE", "type": "human", "factors": ["sms", "push"]},
            {"id": "svc@x", "status": "ACTIVE", "type": "service", "factors": []},
            {"id": "old@x", "status": "DEPROVISIONED", "type": "human", "factors": []},
        ],
    }
    out = okta.normalize(raw)
    assert out["subject_scope"] == "all-human-users"
    assert out["mfa_required_by_policy"] is True
    assert out["phishing_resistant_required_by_policy"] is True
    assert out["users_evaluated"] == 3            # service + deprovisioned excluded
    assert out["users_without_mfa"] == ["bob@x"]
    assert out["users_with_non_phishing_resistant_mfa"] == ["carol@x"]


def test_collect_uses_offline_raw_seam():
    okta = _load()
    out = okta.collect({"raw": {
        "policy": {"mfa_required": True, "phishing_resistant_required": True},
        "users": [{"id": "a@x", "status": "ACTIVE", "type": "human", "factors": ["webauthn"]}],
    }})
    assert out["users_without_mfa"] == []
    assert out["users_evaluated"] == 1
