import importlib.util
from pathlib import Path

COLLECTOR = Path(__file__).resolve().parent.parent / "slices" / "network-restriction" / "collectors" / "gcp.py"


def _load():
    spec = importlib.util.spec_from_file_location("netr_gcp", COLLECTOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_normalize_classifies_ingress_rules():
    gcp = _load()
    raw = {
        "default_deny": True,
        "rules": [
            {"id": "default-allow-ssh", "protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"},   # admin
            {"id": "allow-https", "protocol": "tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0"},       # exception
            {"id": "allow-all", "protocol": "all", "from_port": None, "to_port": None, "cidr": "0.0.0.0/0"},       # all -> admin
        ],
    }
    out = gcp.normalize(raw)
    assert out["rules_evaluated"] == 3
    assert [e["id"] for e in out["public_admin_exposures"]] == ["allow-all", "default-allow-ssh"]
    assert out["unrestricted_ingress"] == []


def test_collect_uses_offline_raw_seam():
    gcp = _load()
    out = gcp.collect({"raw": {
        "default_deny": True,
        "rules": [{"id": "allow-https", "protocol": "tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0"}],
    }})
    assert out["public_admin_exposures"] == []
