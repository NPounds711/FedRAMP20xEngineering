import json
from pathlib import Path

import yaml
from jsonschema import validate

_SCHEMA = Path(__file__).resolve().parent.parent / "schemas" / "slice-mapping.schema.json"


def load_mapping(slice_dir):
    slice_dir = Path(slice_dir)
    data = yaml.safe_load((slice_dir / "mapping.yaml").read_text())
    schema = json.loads(_SCHEMA.read_text())
    validate(instance=data, schema=schema)
    return data
