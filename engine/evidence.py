from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from engine._canonical import canonical_json, sha256_hex

SCHEMA_VERSION = "1.0.0"


@dataclass
class EvidenceRecord:
    schema_version: str
    capability: str
    provider: str
    run_id: str
    collected_at: str
    payload: dict
    payload_sha256: str
    prev_hash: Optional[str]
    record_hash: str


def _now_rfc3339() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _compute_record_hash(capability, provider, run_id, collected_at, payload_sha256, prev_hash) -> str:
    core = {
        "capability": capability,
        "provider": provider,
        "run_id": run_id,
        "collected_at": collected_at,
        "payload_sha256": payload_sha256,
        "prev_hash": prev_hash,
    }
    return sha256_hex(canonical_json(core))


def _chain_path(evidence_dir: Path, capability: str) -> Path:
    return evidence_dir / capability / "chain.jsonl"


def _last_hash(evidence_dir: Path, capability: str) -> Optional[str]:
    cp = _chain_path(evidence_dir, capability)
    if not cp.exists():
        return None
    last = None
    for line in cp.read_text().splitlines():
        if line.strip():
            last = json.loads(line)
    return last["record_hash"] if last else None


def record_evidence(capability, provider, run_id, payload, evidence_dir, collected_at=None) -> EvidenceRecord:
    evidence_dir = Path(evidence_dir)
    collected_at = collected_at or _now_rfc3339()
    payload_sha256 = sha256_hex(canonical_json(payload))
    prev_hash = _last_hash(evidence_dir, capability)
    record_hash = _compute_record_hash(capability, provider, run_id, collected_at, payload_sha256, prev_hash)
    record = EvidenceRecord(
        SCHEMA_VERSION, capability, provider, run_id, collected_at,
        payload, payload_sha256, prev_hash, record_hash,
    )
    cap_dir = evidence_dir / capability
    cap_dir.mkdir(parents=True, exist_ok=True)
    record_file = cap_dir / f"{run_id}.json"
    record_file.write_text(json.dumps(asdict(record), indent=2, sort_keys=True))
    file_sha256 = sha256_hex(record_file.read_bytes())
    with _chain_path(evidence_dir, capability).open("a") as fh:
        fh.write(json.dumps({
            "run_id": run_id,
            "provider": provider,
            "collected_at": collected_at,
            "record_hash": record_hash,
            "prev_hash": prev_hash,
            "file": record_file.name,
            "file_sha256": file_sha256,
        }) + "\n")
    return record


def verify_chain(capability, evidence_dir) -> bool:
    evidence_dir = Path(evidence_dir)
    cp = _chain_path(evidence_dir, capability)
    if not cp.exists():
        return True
    prev = None
    for line in cp.read_text().splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        if entry["prev_hash"] != prev:
            return False
        record_file = evidence_dir / capability / entry["file"]
        rec = json.loads(record_file.read_text())
        recomputed = _compute_record_hash(
            rec["capability"], rec["provider"], rec["run_id"],
            rec["collected_at"], rec["payload_sha256"], rec["prev_hash"],
        )
        if sha256_hex(canonical_json(rec["payload"])) != rec["payload_sha256"]:
            return False
        if recomputed != entry["record_hash"] or rec["record_hash"] != entry["record_hash"]:
            return False
        prev = entry["record_hash"]
    return True
