from engine.render import human as render_human

DETS = [{
    "capability": "fixture", "title": "Fixture Capability", "result": "fail",
    "violations": ["fixture resource not enabled"], "evidence_ref": "b" * 64,
    "collected_at": "2026-06-02T00:00:00Z",
    "frameworks": {"fedramp-20x": [{"ksi": "KSI-FIX-01", "obligation": "required"}],
                   "nist-800-53-rev5": ["ac-1"]},
}]


def test_human_renderer_includes_ksi_control_status_and_evidence():
    text = render_human.render(DETS)
    assert "Fixture Capability" in text
    assert "FAIL" in text
    assert "KSI-FIX-01 (required)" in text
    assert "ac-1" in text
    assert "b" * 64 in text
    assert "fixture resource not enabled" in text
