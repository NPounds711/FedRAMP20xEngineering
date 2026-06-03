from pathlib import Path

from engine.slice import load_mapping

SLICE = Path(__file__).resolve().parent.parent / "slices" / "network-restriction"


def test_mapping_validates_and_targets_the_right_controls():
    m = load_mapping(SLICE)
    assert m["capability"] == "network-restriction"
    assert m["rego_package"] == "fr20x.network_restriction"
    assert {k["id"] for k in m["ksis"]} == {"KSI-CNA-RNT"}
    assert m["ksis"][0]["obligation"] == "required"
    assert set(m["nist_controls"]) == {"ac-17.3", "sc-7.5"}
    assert set(m["providers"]) == {"aws", "azure", "gcp"}
