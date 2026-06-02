from pathlib import Path

from engine.slice import load_mapping

TEMPLATE = Path(__file__).resolve().parent.parent / "slices" / "_TEMPLATE"


def test_template_mapping_validates():
    mapping = load_mapping(TEMPLATE)
    assert mapping["capability"] == "template-capability"
    assert mapping["ksis"][0]["obligation"] in ("required", "recommended")


def test_template_has_required_files():
    for rel in ["collectors/aws.py", "policy/policy.rego",
                "terraform/compliant.tf", "terraform/noncompliant.tf", "README.md"]:
        assert (TEMPLATE / rel).exists(), rel
