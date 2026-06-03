import subprocess
from pathlib import Path

import pytest

from engine.evaluate import opa_available

POLICY_DIR = Path(__file__).resolve().parent.parent / "slices" / "iam-mfa" / "policy"


@pytest.mark.skipif(not opa_available(), reason="opa binary not installed")
def test_opa_unit_tests_pass():
    proc = subprocess.run(
        ["opa", "test", str(POLICY_DIR)],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
