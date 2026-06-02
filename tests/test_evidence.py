import json

from engine.evidence import record_evidence, verify_chain


def test_record_is_deterministic_for_same_inputs(tmp_path):
    args = dict(capability="fixture", provider="aws", run_id="r1",
                payload={"b": 2, "a": 1}, evidence_dir=tmp_path / "d1",
                collected_at="2026-06-02T00:00:00Z")
    r1 = record_evidence(**args)
    args2 = dict(args)
    args2["evidence_dir"] = tmp_path / "d2"
    r2 = record_evidence(**args2)
    assert r1.record_hash == r2.record_hash
    assert r1.payload_sha256 == r2.payload_sha256
    assert r1.prev_hash is None


def test_chain_links_records(tmp_path):
    r1 = record_evidence("fixture", "aws", "r1", {"x": 1}, tmp_path, collected_at="2026-06-02T00:00:00Z")
    r2 = record_evidence("fixture", "aws", "r2", {"x": 2}, tmp_path, collected_at="2026-06-02T00:00:01Z")
    assert r2.prev_hash == r1.record_hash
    assert verify_chain("fixture", tmp_path) is True


def test_verify_detects_payload_tampering(tmp_path):
    record_evidence("fixture", "aws", "r1", {"x": 1}, tmp_path, collected_at="2026-06-02T00:00:00Z")
    record_file = tmp_path / "fixture" / "r1.json"
    doc = json.loads(record_file.read_text())
    doc["payload"]["x"] = 999
    record_file.write_text(json.dumps(doc, indent=2, sort_keys=True))
    assert verify_chain("fixture", tmp_path) is False
