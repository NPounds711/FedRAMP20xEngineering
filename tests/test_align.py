from engine.align import align
from engine.evidence import EvidenceRecord


def _record():
    return EvidenceRecord(
        schema_version="1.0.0", capability="fixture", provider="aws", run_id="r1",
        collected_at="2026-06-02T00:00:00Z", payload={"enabled": True},
        payload_sha256="a" * 64, prev_hash=None, record_hash="b" * 64,
    )


def test_align_attaches_both_frameworks():
    mapping = {
        "capability": "fixture", "title": "Fixture Capability",
        "ksis": [{"id": "KSI-FIX-01", "obligation": "required"}],
        "nist_controls": ["ac-1", "ac-2"],
    }
    det = align(mapping, {"result": "pass", "violations": []}, _record())
    assert det["capability"] == "fixture"
    assert det["result"] == "pass"
    assert det["evidence_ref"] == "b" * 64
    assert det["frameworks"]["fedramp-20x"] == [{"ksi": "KSI-FIX-01", "obligation": "required"}]
    assert det["frameworks"]["nist-800-53-rev5"] == ["ac-1", "ac-2"]
