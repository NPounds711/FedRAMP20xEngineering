from pathlib import Path

import pytest

from engine.slice import load_mapping

FIX = Path(__file__).resolve().parent / "fixtures" / "slice_ok"


def test_load_mapping_returns_validated_dict():
    mapping = load_mapping(FIX)
    assert mapping["capability"] == "fixture"
    assert mapping["ksis"][0]["obligation"] == "required"


def test_load_mapping_rejects_invalid(tmp_path):
    (tmp_path / "mapping.yaml").write_text("capability: BadCaps\n")
    import jsonschema
    with pytest.raises(jsonschema.ValidationError):
        load_mapping(tmp_path)
