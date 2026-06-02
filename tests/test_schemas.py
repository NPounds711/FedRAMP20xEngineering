import json
from pathlib import Path

import jsonschema

SCHEMAS = Path(__file__).resolve().parent.parent / "schemas"


def _load(name):
    return json.loads((SCHEMAS / name).read_text())


def test_all_schemas_are_valid_draft_2020_12():
    for name in ["evidence-record.schema.json", "finding.schema.json", "slice-mapping.schema.json"]:
        schema = _load(name)
        jsonschema.Draft202012Validator.check_schema(schema)


def test_slice_mapping_accepts_valid_mapping():
    schema = _load("slice-mapping.schema.json")
    mapping = {
        "capability": "fixture",
        "title": "Fixture Capability",
        "ksis": [{"id": "KSI-FIX-01", "obligation": "required"}],
        "nist_controls": ["ac-1"],
        "providers": ["fixture"],
        "rego_package": "fr20x.fixture",
    }
    jsonschema.validate(instance=mapping, schema=schema)


def test_slice_mapping_rejects_bad_obligation():
    schema = _load("slice-mapping.schema.json")
    mapping = {
        "capability": "fixture",
        "ksis": [{"id": "KSI-FIX-01", "obligation": "mandatory"}],
        "nist_controls": ["ac-1"],
        "providers": ["fixture"],
        "rego_package": "fr20x.fixture",
    }
    import pytest
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=mapping, schema=schema)
