import importlib.util
from pathlib import Path

COLLECTOR = Path(__file__).resolve().parent.parent / "slices" / "network-restriction" / "collectors" / "azure.py"


def _load():
    spec = importlib.util.spec_from_file_location("netr_azure", COLLECTOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_normalize_classifies_ingress_rules():
    azure = _load()
    raw = {
        "default_deny": True,
        "rules": [
            {"id": "nsg-web/AllowRDP", "protocol": "Tcp", "from_port": 3389, "to_port": 3389, "cidr": "0.0.0.0/0"},  # admin
            {"id": "nsg-web/AllowHTTPS", "protocol": "Tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0"},  # exception
            {"id": "nsg-web/AllowAll", "protocol": "*", "from_port": 8000, "to_port": 9000, "cidr": "0.0.0.0/0"},  # wide non-admin -> unrestricted
            {"id": "nsg-web/Internal", "protocol": "Tcp", "from_port": 1433, "to_port": 1433, "cidr": "10.0.0.0/8"}, # ignored
        ],
    }
    out = azure.normalize(raw)
    assert out["rules_evaluated"] == 4
    assert [e["id"] for e in out["public_admin_exposures"]] == ["nsg-web/AllowRDP"]
    assert [e["id"] for e in out["unrestricted_ingress"]] == ["nsg-web/AllowAll"]


def test_collect_uses_offline_raw_seam():
    azure = _load()
    out = azure.collect({"raw": {
        "default_deny": True,
        "rules": [{"id": "nsg/AllowHTTPS", "protocol": "Tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0"}],
    }})
    assert out["public_admin_exposures"] == []
    assert out["unrestricted_ingress"] == []
