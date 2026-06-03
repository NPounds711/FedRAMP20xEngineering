import importlib.util
from pathlib import Path

COLLECTOR = Path(__file__).resolve().parent.parent / "slices" / "network-restriction" / "collectors" / "aws.py"


def _load():
    spec = importlib.util.spec_from_file_location("netr_aws", COLLECTOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_normalize_classifies_ingress_rules():
    aws = _load()
    raw = {
        "default_deny": True,
        "rules": [
            {"id": "sg-a/tcp/0", "protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"},      # admin
            {"id": "sg-a/tcp/1", "protocol": "tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0"},    # exception, not flagged
            {"id": "sg-a/tcp/2", "protocol": "tcp", "from_port": 5432, "to_port": 5432, "cidr": "10.0.0.0/8"}, # internal, ignored
            {"id": "sg-a/all/3", "protocol": "-1", "from_port": None, "to_port": None, "cidr": "0.0.0.0/0"},   # all-traffic -> admin
            {"id": "sg-a/tcp/4", "protocol": "tcp", "from_port": 8000, "to_port": 9000, "cidr": "0.0.0.0/0"},  # wide -> unrestricted
            {"id": "sg-a/tcp/5", "protocol": "tcp", "from_port": 3389, "to_port": 3389, "cidr": "::/0"},       # admin (rdp, ipv6)
        ],
    }
    out = aws.normalize(raw)
    assert out["scope"] == "ingress-rules"
    assert out["default_deny"] is True
    assert out["rules_evaluated"] == 6
    assert [e["id"] for e in out["public_admin_exposures"]] == ["sg-a/all/3", "sg-a/tcp/0", "sg-a/tcp/5"]
    assert [e["id"] for e in out["unrestricted_ingress"]] == ["sg-a/tcp/4"]
    assert out["public_admin_exposures"][1]["port"] == "22"
    assert out["public_admin_exposures"][0]["port"] == "all"


def test_collect_uses_offline_raw_seam():
    aws = _load()
    out = aws.collect({"raw": {
        "default_deny": True,
        "rules": [{"id": "sg-x/tcp/0", "protocol": "tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0"}],
    }})
    assert out["public_admin_exposures"] == []
    assert out["unrestricted_ingress"] == []
    assert out["rules_evaluated"] == 1
