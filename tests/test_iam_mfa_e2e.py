import importlib.util
import json
from pathlib import Path

import pytest

from engine.cli import main
from engine.evaluate import opa_available

ROOT = Path(__file__).resolve().parent.parent
SLICE = ROOT / "slices" / "iam-mfa"
PROVIDERS = ["okta", "entra", "aws", "gcp"]
PAYLOAD_KEYS = {
    "subject_scope", "mfa_required_by_policy", "phishing_resistant_required_by_policy",
    "users_evaluated", "users_without_mfa", "users_with_non_phishing_resistant_mfa",
}

COMPLIANT_RAW = {
    "policy": {"mfa_required": True, "phishing_resistant_required": True},
    "users": [{"id": "a@x", "status": "ACTIVE", "type": "human", "factors": ["webauthn"]}],
}


def _load(provider):
    path = SLICE / "collectors" / f"{provider}.py"
    spec = importlib.util.spec_from_file_location(f"{provider}_c", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("provider", PROVIDERS)
def test_all_providers_emit_the_same_shape(provider):
    out = _load(provider).collect({"raw": COMPLIANT_RAW})
    assert set(out.keys()) == PAYLOAD_KEYS


@pytest.mark.skipif(not opa_available(), reason="opa binary not installed")
def test_pipeline_end_to_end_via_config(tmp_path, capsys):
    cfg = tmp_path / "okta.json"
    cfg.write_text(json.dumps({"raw": COMPLIANT_RAW}))
    rc = main([
        "run-slice", str(SLICE), "--provider", "okta", "--run-id", "e2e-1",
        "--evidence-dir", str(tmp_path / "ev"), "--config", str(cfg),
    ])
    assert rc == 0
    det = json.loads(capsys.readouterr().out)
    assert det["capability"] == "iam-mfa"
    assert det["result"] == "pass"
    assert det["frameworks"]["nist-800-53-rev5"] == ["ia-2", "ia-2.1", "ia-2.2", "ia-2.8"]
    assert det["frameworks"]["fedramp-20x"][0]["ksi"] == "KSI-IAM-MFA"
    assert main(["verify", "iam-mfa", "--evidence-dir", str(tmp_path / "ev")]) == 0
