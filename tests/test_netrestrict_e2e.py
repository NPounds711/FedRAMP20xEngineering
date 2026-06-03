import importlib.util
import json
from pathlib import Path

import pytest

from engine.cli import main
from engine.evaluate import opa_available

ROOT = Path(__file__).resolve().parent.parent
SLICE = ROOT / "slices" / "network-restriction"
PROVIDERS = ["aws", "azure", "gcp"]
PAYLOAD_KEYS = {
    "scope", "default_deny", "rules_evaluated",
    "public_admin_exposures", "unrestricted_ingress",
}

COMPLIANT_RAW = {
    "default_deny": True,
    "rules": [{"id": "sg/tcp/0", "protocol": "tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0"}],
}
NONCOMPLIANT_RAW = {
    "default_deny": False,
    "rules": [{"id": "sg/tcp/0", "protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"}],
}


def _load(provider):
    path = SLICE / "collectors" / f"{provider}.py"
    spec = importlib.util.spec_from_file_location(f"netr_{provider}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("provider", PROVIDERS)
def test_all_providers_emit_the_same_shape(provider):
    out = _load(provider).collect({"raw": COMPLIANT_RAW})
    assert set(out.keys()) == PAYLOAD_KEYS


@pytest.mark.skipif(not opa_available(), reason="opa binary not installed")
def test_pipeline_pass_via_config(tmp_path, capsys):
    cfg = tmp_path / "aws.json"
    cfg.write_text(json.dumps({"raw": COMPLIANT_RAW}))
    rc = main([
        "run-slice", str(SLICE), "--provider", "aws", "--run-id", "netr-ok",
        "--evidence-dir", str(tmp_path / "ev"), "--config", str(cfg),
    ])
    assert rc == 0
    det = json.loads(capsys.readouterr().out)
    assert det["capability"] == "network-restriction"
    assert det["result"] == "pass"
    assert det["frameworks"]["nist-800-53-rev5"] == ["ac-17.3", "sc-7.5"]
    assert det["frameworks"]["fedramp-20x"][0]["ksi"] == "KSI-CNA-RNT"
    assert main(["verify", "network-restriction", "--evidence-dir", str(tmp_path / "ev")]) == 0


@pytest.mark.skipif(not opa_available(), reason="opa binary not installed")
def test_pipeline_fail_via_config(tmp_path, capsys):
    cfg = tmp_path / "aws.json"
    cfg.write_text(json.dumps({"raw": NONCOMPLIANT_RAW}))
    rc = main([
        "run-slice", str(SLICE), "--provider", "aws", "--run-id", "netr-bad",
        "--evidence-dir", str(tmp_path / "ev"), "--config", str(cfg),
    ])
    assert rc == 0
    det = json.loads(capsys.readouterr().out)
    assert det["result"] == "fail"
    # default_deny false + an SSH-open rule => at least the deny-default and admin violations
    assert len(det["violations"]) >= 2
