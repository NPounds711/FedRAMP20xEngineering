import json

from engine.render import oscal as render_oscal

DETS = [{
    "capability": "fixture", "title": "Fixture Capability", "result": "pass",
    "violations": [], "evidence_ref": "b" * 64, "collected_at": "2026-06-02T00:00:00Z",
    "frameworks": {"fedramp-20x": [{"ksi": "KSI-FIX-01", "obligation": "required"}],
                   "nist-800-53-rev5": ["ac-1"]},
}]


def test_oscal_structure_and_determinism():
    a = render_oscal.render(DETS)
    b = render_oscal.render(DETS)
    assert a == b  # deterministic
    doc = json.loads(a)["assessment-results"]
    assert doc["metadata"]["oscal-version"] == "1.2.0"
    finding = doc["results"][0]["findings"][0]
    assert finding["target"]["status"]["state"] == "satisfied"
    ctrls = finding["related-controls"]["control-selections"][0]["include-controls"]
    assert {"control-id": "ac-1"} in ctrls
    assert finding["props"][0]["value"] == "b" * 64
