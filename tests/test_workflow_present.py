from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
WF = ROOT / ".github" / "workflows" / "frmr-sync.yml"


def test_workflow_is_valid_and_wired():
    assert WF.exists()
    wf = yaml.safe_load(WF.read_text())
    triggers = wf.get("on", wf.get(True))   # 'on' parses as True in YAML 1.1
    assert "schedule" in triggers and "workflow_dispatch" in triggers
    text = WF.read_text()
    assert "tools.frmr_drift" in text and "--apply" in text
    assert "create-pull-request" in text
    assert "reviewers" in text and "frmr-sync" in text
    assert "action-send-mail" in text


def test_onboarding_doc_present():
    doc = (ROOT / "docs" / "onboarding" / "auto-sync.md").read_text()
    assert "Allow GitHub Actions to create and approve pull requests" in doc
    assert "secret" in doc.lower()
