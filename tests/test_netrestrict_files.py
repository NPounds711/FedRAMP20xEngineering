from pathlib import Path

SLICE = Path(__file__).resolve().parent.parent / "slices" / "network-restriction"


def test_slice_has_all_required_files():
    required = [
        "mapping.yaml", "README.md",
        "policy/policy.rego", "policy/policy_test.rego",
        "collectors/aws.py", "collectors/azure.py", "collectors/gcp.py",
        "terraform/compliant.tf", "terraform/noncompliant.tf",
    ]
    for rel in required:
        assert (SLICE / rel).exists(), rel
