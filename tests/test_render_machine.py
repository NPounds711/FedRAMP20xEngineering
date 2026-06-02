import json

import yaml

from engine.render import json as render_json
from engine.render import yaml as render_yaml

DETS = [{
    "capability": "fixture", "title": "Fixture Capability", "result": "pass",
    "violations": [], "evidence_ref": "b" * 64, "collected_at": "2026-06-02T00:00:00Z",
    "frameworks": {"fedramp-20x": [{"ksi": "KSI-FIX-01", "obligation": "required"}],
                   "nist-800-53-rev5": ["ac-1"]},
}]


def test_json_renderer_round_trips():
    text = render_json.render(DETS)
    assert json.loads(text)["determinations"][0]["capability"] == "fixture"


def test_yaml_renderer_round_trips():
    text = render_yaml.render(DETS)
    assert yaml.safe_load(text)["determinations"][0]["frameworks"]["nist-800-53-rev5"] == ["ac-1"]
