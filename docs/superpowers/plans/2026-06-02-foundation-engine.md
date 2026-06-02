# FedRAMP20x Foundation & Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the framework-agnostic evidence engine — collect a security fact once, hash/timestamp/chain it, evaluate it with OPA/Rego, align it to both 20x KSIs and Rev 5 NIST controls, and render it to OSCAL/JSON/YAML/human — plus the catalog sync and a runnable `fr20x` CLI, proven end-to-end on a built-in fixture slice.

**Architecture:** A small Python package `engine/` of single-responsibility modules (`evidence`, `collect`, `evaluate`, `align`, `render/*`, `report`, `slice`, `cli`) plus `tools/sync.py`. Slices are data + Rego + collectors discovered at runtime. No LLM in the evaluation path; OPA/Rego does evaluation so a 3PAO can re-run for byte-identical verdicts. The fixture slice (`slices/_fixture/`) exercises the whole pipeline in tests; `slices/_TEMPLATE/` is the copy-me starting point for real slices.

**Tech Stack:** Python 3.12, pytest, PyYAML, jsonschema, Open Policy Agent (`opa` binary), argparse CLI exposed as the `fr20x` console script.

**Working rules (do not violate):** Commit locally only — never push or merge (the repo owner does that). Never add an AI-attribution trailer or any reference to the drafting tool in commits or content. Commit with `git -c commit.gpgsign=false commit`.

---

## Module contracts (locked — later tasks must match these exactly)

- `engine/_canonical.py`: `canonical_json(obj) -> bytes`, `sha256_hex(data: bytes) -> str`.
- `engine/evidence.py`: `record_evidence(capability, provider, run_id, payload, evidence_dir, collected_at=None) -> EvidenceRecord`; `verify_chain(capability, evidence_dir) -> bool`. `EvidenceRecord` is a dataclass with fields `schema_version, capability, provider, run_id, collected_at, payload, payload_sha256, prev_hash, record_hash`.
- `engine/slice.py`: `load_mapping(slice_dir) -> dict`.
- `engine/collect.py`: `collect(slice_dir, provider, config=None) -> dict`.
- `engine/evaluate.py`: `evaluate(policy_dir, rego_package, input_data) -> {"result": "pass"|"fail", "violations": [...]}`; `opa_available() -> bool`; exception `OpaNotInstalled`.
- `engine/align.py`: `align(mapping, eval_result, evidence_record) -> determination dict`.
- `engine/render/{json,yaml,oscal,human}.py`: each exposes `render(determinations: list[dict]) -> str` (oscal also accepts `timestamp=None`).
- `engine/report.py`: `load_ksi_index(path) -> list[dict]`; `coverage(ksi_index, determinations) -> dict`.
- `tools/sync.py`: `extract_obligations(frmr_ksi_doc) -> dict`; `diff_catalog(old_doc, new_doc) -> dict`; `sync(dest, offline_dir=None) -> dict`.

**Determination shape** (output of `align`, input of every renderer and report):
```json
{
  "capability": "fixture",
  "title": "Fixture Capability",
  "result": "pass",
  "violations": [],
  "evidence_ref": "<record_hash>",
  "collected_at": "2026-06-02T00:00:00Z",
  "frameworks": {
    "fedramp-20x": [{"ksi": "KSI-FIX-01", "obligation": "required"}],
    "nist-800-53-rev5": ["ac-1"]
  }
}
```

**Rego result contract:** every slice's policy defines, under its declared package, a single decision document `result := {"pass": <bool>, "violations": [<string>...]}`.

---

### Task 0: Repository scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `engine/__init__.py`, `engine/render/__init__.py`, `tools/__init__.py`, `tests/__init__.py`
- Create: `.gitignore`
- Create: `NOTICE.md`

- [ ] **Step 1: Create `pyproject.toml`**

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "fedramp20x-engineering"
version = "0.1.0"
description = "FedRAMP advisory + framework-agnostic evidence toolkit"
requires-python = ">=3.12"
dependencies = ["PyYAML>=6.0", "jsonschema>=4.21"]

[project.optional-dependencies]
dev = ["pytest>=8.0"]

[project.scripts]
fr20x = "engine.cli:main"

[tool.setuptools]
packages = ["engine", "engine.render", "tools"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

- [ ] **Step 2: Create the empty package files**

Create `engine/__init__.py`, `engine/render/__init__.py`, `tools/__init__.py`, `tests/__init__.py` each containing a single comment line:
```python
# package marker
```

- [ ] **Step 3: Create `.gitignore`**

```gitignore
__pycache__/
*.pyc
.venv/
.pytest_cache/
*.egg-info/
/evidence/
```

- [ ] **Step 4: Create `NOTICE.md`**

```markdown
# Notices and Attribution

This repository adapts patterns from the following sources. They are credited here;
their inclusion does not imply endorsement.

- **GRCEngClub/claude-grc-engineering** (https://github.com/GRCEngClub/claude-grc-engineering)
  — the shape of the connector finding contract, connector design patterns, and the
  approach to syncing FedRAMP machine-readable policy files from `FedRAMP/docs`.
- **FedRAMP/docs** (https://github.com/FedRAMP/docs) — authoritative FRMR machine-readable
  policy files (Key Security Indicators and supporting standards), synced into `catalog/`.
- **FedRAMP automation** — NIST 800-53 Rev 5 OSCAL baselines, synced into `catalog/rev5/`.

All code in `engine/`, `tools/`, `slices/`, and `schemas/` is original to this repository.
```

- [ ] **Step 5: Install editable and verify import path**

Run: `python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"`
Expected: installs successfully; `python -c "import engine, tools"` exits 0.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml engine tools tests .gitignore NOTICE.md
git -c commit.gpgsign=false commit -m "Scaffold engine package, tooling, and attribution notice"
```

---

### Task 1: Canonical JSON + hashing utility

**Files:**
- Create: `engine/_canonical.py`
- Test: `tests/test_canonical.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_canonical.py
from engine._canonical import canonical_json, sha256_hex


def test_canonical_json_is_order_independent():
    a = canonical_json({"b": 1, "a": 2})
    b = canonical_json({"a": 2, "b": 1})
    assert a == b == b'{"a":2,"b":1}'


def test_sha256_hex_is_stable_and_64_chars():
    h = sha256_hex(b"hello")
    assert h == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    assert len(h) == 64
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_canonical.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'engine._canonical'`

- [ ] **Step 3: Write minimal implementation**

```python
# engine/_canonical.py
import hashlib
import json


def canonical_json(obj) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_canonical.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add engine/_canonical.py tests/test_canonical.py
git -c commit.gpgsign=false commit -m "Add canonical JSON and sha256 helper"
```

---

### Task 2: JSON Schemas (evidence record, finding, slice mapping)

**Files:**
- Create: `schemas/evidence-record.schema.json`
- Create: `schemas/finding.schema.json`
- Create: `schemas/slice-mapping.schema.json`
- Test: `tests/test_schemas.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_schemas.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_schemas.py -v`
Expected: FAIL — files do not exist (`FileNotFoundError`).

- [ ] **Step 3: Create `schemas/evidence-record.schema.json`**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Evidence Record",
  "type": "object",
  "required": ["schema_version", "capability", "provider", "run_id", "collected_at", "payload", "payload_sha256", "prev_hash", "record_hash"],
  "additionalProperties": false,
  "properties": {
    "schema_version": {"const": "1.0.0"},
    "capability": {"type": "string"},
    "provider": {"type": "string"},
    "run_id": {"type": "string", "minLength": 1},
    "collected_at": {"type": "string", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"},
    "payload": {"type": "object"},
    "payload_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "prev_hash": {"type": ["string", "null"], "pattern": "^[0-9a-f]{64}$"},
    "record_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
  }
}
```

- [ ] **Step 4: Create `schemas/finding.schema.json`**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Determination",
  "description": "Framework-agnostic determination: one collected fact aligned to all controls/KSIs it satisfies.",
  "type": "object",
  "required": ["capability", "result", "evidence_ref", "collected_at", "frameworks"],
  "additionalProperties": false,
  "properties": {
    "capability": {"type": "string"},
    "title": {"type": "string"},
    "result": {"enum": ["pass", "fail"]},
    "violations": {"type": "array", "items": {"type": "string"}},
    "evidence_ref": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "collected_at": {"type": "string"},
    "frameworks": {
      "type": "object",
      "required": ["fedramp-20x", "nist-800-53-rev5"],
      "properties": {
        "fedramp-20x": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["ksi", "obligation"],
            "properties": {
              "ksi": {"type": "string"},
              "obligation": {"enum": ["required", "recommended"]}
            }
          }
        },
        "nist-800-53-rev5": {"type": "array", "items": {"type": "string"}}
      }
    }
  }
}
```

- [ ] **Step 5: Create `schemas/slice-mapping.schema.json`**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Slice Mapping",
  "type": "object",
  "required": ["capability", "ksis", "nist_controls", "providers", "rego_package"],
  "additionalProperties": true,
  "properties": {
    "capability": {"type": "string", "pattern": "^[a-z][a-z0-9-]*$"},
    "title": {"type": "string"},
    "ksis": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["id", "obligation"],
        "properties": {
          "id": {"type": "string"},
          "obligation": {"enum": ["required", "recommended"]}
        }
      }
    },
    "nist_controls": {"type": "array", "items": {"type": "string"}},
    "providers": {"type": "array", "items": {"type": "string"}},
    "evidence_source": {"type": "string"},
    "rego_package": {"type": "string"}
  }
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/test_schemas.py -v`
Expected: PASS (3 passed)

- [ ] **Step 7: Commit**

```bash
git add schemas tests/test_schemas.py
git -c commit.gpgsign=false commit -m "Add evidence-record, finding, and slice-mapping schemas"
```

---

### Task 3: Evidence integrity (timestamp + hash + chain)

**Files:**
- Create: `engine/evidence.py`
- Test: `tests/test_evidence.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_evidence.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_evidence.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'engine.evidence'`

- [ ] **Step 3: Write the implementation**

```python
# engine/evidence.py
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
        # payload integrity: the stored payload hash must still match the stored payload
        if sha256_hex(canonical_json(rec["payload"])) != rec["payload_sha256"]:
            return False
        if recomputed != entry["record_hash"] or rec["record_hash"] != entry["record_hash"]:
            return False
        prev = entry["record_hash"]
    return True
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_evidence.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add engine/evidence.py tests/test_evidence.py
git -c commit.gpgsign=false commit -m "Add evidence integrity: timestamp, hashing, and chain verification"
```

---

### Task 4: Slice mapping loader

**Files:**
- Create: `engine/slice.py`
- Test: `tests/test_slice.py`
- Test fixture: `tests/fixtures/slice_ok/mapping.yaml`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_slice.py
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
```

- [ ] **Step 2: Create the test fixture `tests/fixtures/slice_ok/mapping.yaml`**

```yaml
capability: fixture
title: Fixture Capability
ksis:
  - id: KSI-FIX-01
    obligation: required
nist_controls:
  - ac-1
providers:
  - fixture
evidence_source: "fixture in-memory data"
rego_package: fr20x.fixture
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_slice.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'engine.slice'`

- [ ] **Step 4: Write the implementation**

```python
# engine/slice.py
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_slice.py -v`
Expected: PASS (2 passed)

- [ ] **Step 6: Commit**

```bash
git add engine/slice.py tests/test_slice.py tests/fixtures/slice_ok/mapping.yaml
git -c commit.gpgsign=false commit -m "Add slice mapping loader with schema validation"
```

---

### Task 5: Collector loader

**Files:**
- Create: `engine/collect.py`
- Test: `tests/test_collect.py`
- Test fixture: `tests/fixtures/slice_ok/collectors/fixture.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_collect.py
from pathlib import Path

import pytest

from engine.collect import collect

FIX = Path(__file__).resolve().parent / "fixtures" / "slice_ok"


def test_collect_runs_provider_module():
    out = collect(FIX, "fixture", {"enabled": True})
    assert out == {"enabled": True, "resource_id": "fixture-1"}


def test_collect_missing_provider_raises():
    with pytest.raises(FileNotFoundError):
        collect(FIX, "nope", {})
```

- [ ] **Step 2: Create the fixture collector `tests/fixtures/slice_ok/collectors/fixture.py`**

```python
# fixture collector — returns a normalized in-memory payload
def collect(config):
    return {
        "enabled": config.get("enabled", True),
        "resource_id": config.get("resource_id", "fixture-1"),
    }
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_collect.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'engine.collect'`

- [ ] **Step 4: Write the implementation**

```python
# engine/collect.py
import importlib.util
from pathlib import Path


def _load_collector(slice_dir, provider):
    path = Path(slice_dir) / "collectors" / f"{provider}.py"
    if not path.exists():
        raise FileNotFoundError(f"no collector for provider '{provider}' in {slice_dir}")
    spec = importlib.util.spec_from_file_location(f"collector_{provider}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def collect(slice_dir, provider, config=None):
    module = _load_collector(slice_dir, provider)
    return module.collect(config or {})
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_collect.py -v`
Expected: PASS (2 passed)

- [ ] **Step 6: Commit**

```bash
git add engine/collect.py tests/test_collect.py tests/fixtures/slice_ok/collectors/fixture.py
git -c commit.gpgsign=false commit -m "Add dynamic per-provider collector loader"
```

---

### Task 6: OPA/Rego evaluator

**Files:**
- Create: `engine/evaluate.py`
- Test: `tests/test_evaluate.py`
- Test fixture: `tests/fixtures/slice_ok/policy/fixture.rego`

**Prerequisite note:** Tasks 6 and 13 require the `opa` binary on `PATH`. Install: macOS `brew install opa`; Linux download from https://github.com/open-policy-agent/opa/releases. CI must install it. Tests skip gracefully when `opa` is absent so the rest of the suite still runs.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_evaluate.py
from pathlib import Path

import pytest

from engine.evaluate import evaluate, opa_available

FIX = Path(__file__).resolve().parent / "fixtures" / "slice_ok"

pytestmark = pytest.mark.skipif(not opa_available(), reason="opa binary not installed")


def test_evaluate_pass():
    out = evaluate(FIX / "policy", "fr20x.fixture", {"enabled": True})
    assert out == {"result": "pass", "violations": []}


def test_evaluate_fail_collects_violations():
    out = evaluate(FIX / "policy", "fr20x.fixture", {"enabled": False})
    assert out["result"] == "fail"
    assert "fixture resource not enabled" in out["violations"]
```

- [ ] **Step 2: Create the fixture policy `tests/fixtures/slice_ok/policy/fixture.rego`**

```rego
package fr20x.fixture

import rego.v1

violations contains msg if {
	input.enabled != true
	msg := "fixture resource not enabled"
}

result := {"pass": count(violations) == 0, "violations": violations}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_evaluate.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'engine.evaluate'` (or SKIPPED if opa absent — install opa to run this task).

- [ ] **Step 4: Write the implementation**

```python
# engine/evaluate.py
import json
import shutil
import subprocess
import tempfile
from pathlib import Path


class OpaNotInstalled(RuntimeError):
    pass


def opa_available() -> bool:
    return shutil.which("opa") is not None


def evaluate(policy_dir, rego_package, input_data) -> dict:
    if not opa_available():
        raise OpaNotInstalled(
            "opa binary not found on PATH; install from "
            "https://github.com/open-policy-agent/opa/releases"
        )
    query = f"data.{rego_package}.result"
    tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    try:
        json.dump(input_data, tf)
        tf.close()
        proc = subprocess.run(
            ["opa", "eval", "--format", "json", "-d", str(policy_dir), "-i", tf.name, query],
            capture_output=True, text=True, check=True,
        )
    finally:
        Path(tf.name).unlink(missing_ok=True)
    out = json.loads(proc.stdout)
    results = out.get("result", [])
    if not results:
        return {"result": "fail", "violations": ["policy produced no result document"]}
    value = results[0]["expressions"][0]["value"]
    return {
        "result": "pass" if value.get("pass") else "fail",
        "violations": list(value.get("violations", [])),
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_evaluate.py -v`
Expected: PASS (2 passed) when opa installed.

- [ ] **Step 6: Commit**

```bash
git add engine/evaluate.py tests/test_evaluate.py tests/fixtures/slice_ok/policy/fixture.rego
git -c commit.gpgsign=false commit -m "Add OPA/Rego evaluator with result-document contract"
```

---

### Task 7: Alignment (one fact → both frameworks)

**Files:**
- Create: `engine/align.py`
- Test: `tests/test_align.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_align.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_align.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'engine.align'`

- [ ] **Step 3: Write the implementation**

```python
# engine/align.py
def align(mapping, eval_result, evidence_record):
    return {
        "capability": mapping["capability"],
        "title": mapping.get("title", mapping["capability"]),
        "result": eval_result["result"],
        "violations": list(eval_result.get("violations", [])),
        "evidence_ref": evidence_record.record_hash,
        "collected_at": evidence_record.collected_at,
        "frameworks": {
            "fedramp-20x": [
                {"ksi": k["id"], "obligation": k.get("obligation", "required")}
                for k in mapping.get("ksis", [])
            ],
            "nist-800-53-rev5": list(mapping.get("nist_controls", [])),
        },
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_align.py -v`
Expected: PASS (1 passed)

- [ ] **Step 5: Commit**

```bash
git add engine/align.py tests/test_align.py
git -c commit.gpgsign=false commit -m "Add alignment: map one evidence fact to 20x KSIs and Rev 5 controls"
```

---

### Task 8: JSON and YAML renderers

**Files:**
- Create: `engine/render/json.py`
- Create: `engine/render/yaml.py`
- Test: `tests/test_render_machine.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_render_machine.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_render_machine.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'engine.render.json'`

- [ ] **Step 3: Write `engine/render/json.py`**

```python
# engine/render/json.py
import json


def render(determinations) -> str:
    return json.dumps({"determinations": list(determinations)}, indent=2, sort_keys=True)
```

- [ ] **Step 4: Write `engine/render/yaml.py`**

```python
# engine/render/yaml.py
import yaml


def render(determinations) -> str:
    return yaml.safe_dump({"determinations": list(determinations)}, sort_keys=True)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_render_machine.py -v`
Expected: PASS (2 passed)

- [ ] **Step 6: Commit**

```bash
git add engine/render/json.py engine/render/yaml.py tests/test_render_machine.py
git -c commit.gpgsign=false commit -m "Add JSON and YAML machine-readable renderers"
```

---

### Task 9: OSCAL renderer (minimal assessment-results 1.2.0)

**Files:**
- Create: `engine/render/oscal.py`
- Test: `tests/test_render_oscal.py`

**Note:** v1 emits a minimal, valid-shaped OSCAL `assessment-results` document (deterministic uuid5-derived UUIDs, no randomness). Full OSCAL schema validation is a follow-on (the spec's `oscal` tooling); this renderer's contract is the structure asserted in the test.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_render_oscal.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_render_oscal.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'engine.render.oscal'`

- [ ] **Step 3: Write the implementation**

```python
# engine/render/oscal.py
import json
import uuid as uuidlib

_NS = uuidlib.UUID("12345678-1234-5678-1234-567812345678")


def _uid(name: str) -> str:
    return str(uuidlib.uuid5(_NS, name))


def render(determinations, timestamp=None) -> str:
    determinations = list(determinations)
    ts = timestamp or (determinations[0]["collected_at"] if determinations else "1970-01-01T00:00:00Z")
    findings = []
    for d in determinations:
        controls = list(d["frameworks"].get("nist-800-53-rev5", []))
        findings.append({
            "uuid": _uid("finding:" + d["capability"]),
            "title": d.get("title", d["capability"]),
            "target": {
                "type": "objective-id",
                "target-id": d["capability"],
                "status": {"state": "satisfied" if d["result"] == "pass" else "not-satisfied"},
            },
            "related-controls": {
                "control-selections": [
                    {"include-controls": [{"control-id": c} for c in controls]}
                ]
            },
            "props": [
                {"name": "evidence-hash", "ns": "https://fedramp.gov/ns/20x", "value": d["evidence_ref"]}
            ],
        })
    doc = {
        "assessment-results": {
            "uuid": _uid("assessment-results"),
            "metadata": {
                "title": "FedRAMP20x Automated Evidence",
                "version": "1.0.0",
                "oscal-version": "1.2.0",
                "last-modified": ts,
            },
            "import-ap": {"href": "#"},
            "results": [
                {
                    "uuid": _uid("result"),
                    "title": "Automated evidence collection",
                    "start": ts,
                    "findings": findings,
                }
            ],
        }
    }
    return json.dumps(doc, indent=2, sort_keys=True)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_render_oscal.py -v`
Expected: PASS (1 passed)

- [ ] **Step 5: Commit**

```bash
git add engine/render/oscal.py tests/test_render_oscal.py
git -c commit.gpgsign=false commit -m "Add minimal OSCAL assessment-results renderer"
```

---

### Task 10: Human-readable renderer (reconciles with machine output)

**Files:**
- Create: `engine/render/human.py`
- Test: `tests/test_render_human.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_render_human.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_render_human.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'engine.render.human'`

- [ ] **Step 3: Write the implementation**

```python
# engine/render/human.py
def render(determinations) -> str:
    lines = ["# FedRAMP Evidence Summary", ""]
    for d in determinations:
        ksis = ", ".join(
            f"{k['ksi']} ({k['obligation']})" for k in d["frameworks"]["fedramp-20x"]
        )
        controls = ", ".join(d["frameworks"]["nist-800-53-rev5"])
        status = "PASS" if d["result"] == "pass" else "FAIL"
        lines += [
            f"## {d.get('title', d['capability'])} — {status}",
            f"- Capability: `{d['capability']}`",
            f"- 20x KSIs: {ksis or 'none'}",
            f"- Rev 5 controls: {controls or 'none'}",
            f"- Evidence hash: `{d['evidence_ref']}`",
            f"- Collected at: {d['collected_at']}",
        ]
        if d["result"] != "pass" and d.get("violations"):
            lines.append(f"- Violations: {'; '.join(map(str, d['violations']))}")
        lines.append("")
    return "\n".join(lines)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_render_human.py -v`
Expected: PASS (1 passed)

- [ ] **Step 5: Commit**

```bash
git add engine/render/human.py tests/test_render_human.py
git -c commit.gpgsign=false commit -m "Add human-readable renderer that reconciles with machine output"
```

---

### Task 11: Coverage + required/recommended report

**Files:**
- Create: `engine/report.py`
- Test: `tests/test_report.py`
- Test fixture: `tests/fixtures/ksi_index.csv`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_report.py
from pathlib import Path

from engine.report import coverage, load_ksi_index

FIX = Path(__file__).resolve().parent / "fixtures" / "ksi_index.csv"


def _det(ksi, obligation, result):
    return {
        "capability": ksi.lower(), "result": result, "evidence_ref": "b" * 64,
        "collected_at": "2026-06-02T00:00:00Z",
        "frameworks": {"fedramp-20x": [{"ksi": ksi, "obligation": obligation}],
                       "nist-800-53-rev5": []},
    }


def test_load_ksi_index_reads_obligation():
    idx = load_ksi_index(FIX)
    assert {"ksi": "KSI-A", "obligation": "required"} in idx


def test_coverage_math_and_gap_ordering():
    idx = load_ksi_index(FIX)  # KSI-A required, KSI-B required, KSI-C recommended, KSI-D recommended
    dets = [_det("KSI-A", "required", "pass"), _det("KSI-C", "recommended", "pass")]
    cov = coverage(idx, dets)
    assert cov["total_ksis"] == 4
    assert cov["automated_pct"] == 50.0
    assert cov["meets_70_threshold"] is False
    assert cov["required_addressed"] == "1/2"
    assert cov["recommended_addressed"] == "1/2"
    # required gaps ranked before recommended gaps
    assert cov["gaps"][0]["obligation"] == "required"
    assert cov["gaps"][0]["ksi"] == "KSI-B"
```

- [ ] **Step 2: Create the fixture `tests/fixtures/ksi_index.csv`**

```csv
KSI_ID,Obligation
KSI-A,required
KSI-B,required
KSI-C,recommended
KSI-D,recommended
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_report.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'engine.report'`

- [ ] **Step 4: Write the implementation**

```python
# engine/report.py
import csv


def load_ksi_index(path):
    rows = []
    with open(path, newline="") as fh:
        for row in csv.DictReader(fh):
            rows.append({
                "ksi": row["KSI_ID"].strip(),
                "obligation": (row.get("Obligation") or "required").strip().lower(),
            })
    return rows


def coverage(ksi_index, determinations):
    addressed = set()
    for d in determinations:
        if d["result"] == "pass":
            for k in d["frameworks"]["fedramp-20x"]:
                addressed.add(k["ksi"])
    total = len(ksi_index)
    required = [k for k in ksi_index if k["obligation"] == "required"]
    recommended = [k for k in ksi_index if k["obligation"] == "recommended"]
    req_addr = [k for k in required if k["ksi"] in addressed]
    rec_addr = [k for k in recommended if k["ksi"] in addressed]
    pct = (len(addressed) / total * 100) if total else 0.0
    gaps = [k for k in ksi_index if k["ksi"] not in addressed]
    gaps.sort(key=lambda k: 0 if k["obligation"] == "required" else 1)
    return {
        "total_ksis": total,
        "automated_pct": round(pct, 1),
        "meets_70_threshold": pct >= 70.0,
        "required_addressed": f"{len(req_addr)}/{len(required)}",
        "recommended_addressed": f"{len(rec_addr)}/{len(recommended)}",
        "gaps": [{"ksi": k["ksi"], "obligation": k["obligation"]} for k in gaps],
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_report.py -v`
Expected: PASS (2 passed)

- [ ] **Step 6: Commit**

```bash
git add engine/report.py tests/test_report.py tests/fixtures/ksi_index.csv
git -c commit.gpgsign=false commit -m "Add coverage report with required/recommended rollup and gap ordering"
```

---

### Task 12: Catalog sync (FRMR obligations + diff + offline mode)

**Files:**
- Create: `tools/sync.py`
- Test: `tests/test_sync.py`
- Test fixtures: `tests/fixtures/frmr_old/FRMR.KSI.key-security-indicators.json`, `tests/fixtures/frmr_new/FRMR.KSI.key-security-indicators.json`

**Note on FRMR shape:** `extract_obligations` walks an assumed FRMR structure (families → indicators with a MUST/SHOULD `indicator` field). After the first live sync, verify the real field names against `FedRAMP/docs` and adjust this one function plus its fixtures if they differ. The test pins the contract; the fixtures mirror the assumed shape.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_sync.py
import json
from pathlib import Path

from tools.sync import diff_catalog, extract_obligations, sync

FIX = Path(__file__).resolve().parent / "fixtures"


def test_extract_obligations_maps_must_and_should():
    doc = json.loads((FIX / "frmr_old" / "FRMR.KSI.key-security-indicators.json").read_text())
    obs = extract_obligations(doc)
    assert obs["KSI-A"] == "required"
    assert obs["KSI-C"] == "recommended"


def test_diff_catalog_reports_added_removed_and_changed():
    old = json.loads((FIX / "frmr_old" / "FRMR.KSI.key-security-indicators.json").read_text())
    new = json.loads((FIX / "frmr_new" / "FRMR.KSI.key-security-indicators.json").read_text())
    d = diff_catalog(old, new)
    assert d["added"] == ["KSI-D"]
    assert d["removed"] == ["KSI-B"]
    assert d["obligation_changed"] == ["KSI-C"]


def test_sync_offline_copies_files(tmp_path):
    written = sync(tmp_path / "out", offline_dir=FIX / "frmr_old")
    assert "FRMR.KSI.key-security-indicators.json" in written
    assert (tmp_path / "out" / "FRMR.KSI.key-security-indicators.json").exists()
```

- [ ] **Step 2: Create fixture `tests/fixtures/frmr_old/FRMR.KSI.key-security-indicators.json`**

```json
{
  "FRMR": {
    "KSI": [
      {"family": "FIX", "indicators": [
        {"id": "KSI-A", "indicator": "MUST do A"},
        {"id": "KSI-B", "indicator": "MUST do B"},
        {"id": "KSI-C", "indicator": "SHOULD do C"}
      ]}
    ]
  }
}
```

- [ ] **Step 3: Create fixture `tests/fixtures/frmr_new/FRMR.KSI.key-security-indicators.json`**

```json
{
  "FRMR": {
    "KSI": [
      {"family": "FIX", "indicators": [
        {"id": "KSI-A", "indicator": "MUST do A"},
        {"id": "KSI-C", "indicator": "MUST do C"},
        {"id": "KSI-D", "indicator": "SHOULD do D"}
      ]}
    ]
  }
}
```

- [ ] **Step 4: Run test to verify it fails**

Run: `pytest tests/test_sync.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'tools.sync'`

- [ ] **Step 5: Write the implementation**

```python
# tools/sync.py
import urllib.request
from pathlib import Path

FRMR_BASE = "https://raw.githubusercontent.com/FedRAMP/docs/main/"
FRMR_FILES = [
    "FRMR.KSI.key-security-indicators.json",
    "FRMR.VDR.vulnerability-detection-and-response.json",
    "FRMR.MAS.minimum-assessment-scope.json",
    "FRMR.PVA.persistent-validation-and-assessment.json",
    "FRMR.ICP.incident-communications-procedures.json",
    "FRMR.SCN.significant-change-notifications.json",
    "FRMR.CCM.collaborative-continuous-monitoring.json",
    "FRMR.ADS.authorization-data-sharing.json",
    "FRMR.RSC.recommended-secure-configuration.json",
    "FRMR.UCM.using-cryptographic-modules.json",
    "FRMR.FSI.fedramp-security-inbox.json",
    "FRMR.FRD.fedramp-definitions.json",
]


def extract_obligations(frmr_ksi_doc) -> dict:
    """Map KSI id -> 'required' (MUST) | 'recommended' (SHOULD).

    Assumes FRMR shape: {"FRMR": {"KSI": [{"indicators": [{"id", "indicator"}]}]}}.
    Verify field names against live FedRAMP/docs after the first sync.
    """
    out = {}
    for family in frmr_ksi_doc.get("FRMR", {}).get("KSI", []):
        for indicator in family.get("indicators", []):
            text = str(indicator.get("indicator", "")).upper()
            out[indicator["id"]] = "required" if text.startswith("MUST") else "recommended"
    return out


def diff_catalog(old_doc, new_doc) -> dict:
    old = extract_obligations(old_doc)
    new = extract_obligations(new_doc)
    return {
        "added": sorted(set(new) - set(old)),
        "removed": sorted(set(old) - set(new)),
        "obligation_changed": sorted(k for k in (set(old) & set(new)) if old[k] != new[k]),
    }


def _fetch(url: str) -> str:
    with urllib.request.urlopen(url) as response:  # noqa: S310 - public FedRAMP docs
        return response.read().decode("utf-8")


def sync(dest, offline_dir=None) -> dict:
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    written = {}
    for fname in FRMR_FILES:
        if offline_dir is not None:
            source = Path(offline_dir) / fname
            if not source.exists():
                continue
            content = source.read_text()
        else:
            content = _fetch(FRMR_BASE + fname)
        (dest / fname).write_text(content)
        written[fname] = len(content)
    return written
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/test_sync.py -v`
Expected: PASS (3 passed)

- [ ] **Step 7: Commit**

```bash
git add tools/sync.py tests/test_sync.py tests/fixtures/frmr_old tests/fixtures/frmr_new
git -c commit.gpgsign=false commit -m "Add catalog sync: FRMR obligation extraction, diff, and offline mode"
```

---

### Task 13: CLI wiring + the `_fixture` slice end-to-end

**Files:**
- Create: `engine/cli.py`
- Create: `slices/_fixture/mapping.yaml`
- Create: `slices/_fixture/collectors/fixture.py`
- Create: `slices/_fixture/policy/fixture.rego`
- Create: `slices/_fixture/README.md`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Create the `_fixture` slice files**

`slices/_fixture/mapping.yaml`:
```yaml
capability: fixture
title: Fixture Capability
ksis:
  - id: KSI-FIX-01
    obligation: required
nist_controls:
  - ac-1
providers:
  - fixture
evidence_source: "fixture in-memory data"
rego_package: fr20x.fixture
```

`slices/_fixture/collectors/fixture.py`:
```python
# fixture collector — returns a normalized in-memory payload
def collect(config):
    return {
        "enabled": config.get("enabled", True),
        "resource_id": config.get("resource_id", "fixture-1"),
    }
```

`slices/_fixture/policy/fixture.rego`:
```rego
package fr20x.fixture

import rego.v1

violations contains msg if {
	input.enabled != true
	msg := "fixture resource not enabled"
}

result := {"pass": count(violations) == 0, "violations": violations}
```

`slices/_fixture/README.md`:
```markdown
# `_fixture` slice

A built-in smoke slice that exercises the whole pipeline (collect → record → evaluate
→ align → render) without touching any cloud provider. Used by the test suite and as a
live demo: `fr20x run-slice slices/_fixture --provider fixture --run-id demo-1`.
Not a real control — see `slices/_TEMPLATE/` to build a real one.
```

- [ ] **Step 2: Write the failing test**

```python
# tests/test_cli.py
import json
from pathlib import Path

import pytest

from engine.cli import main
from engine.evaluate import opa_available

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_SLICE = ROOT / "slices" / "_fixture"


def test_render_and_report_subcommands(tmp_path, capsys):
    det = {
        "capability": "fixture", "title": "Fixture Capability", "result": "pass",
        "violations": [], "evidence_ref": "b" * 64, "collected_at": "2026-06-02T00:00:00Z",
        "frameworks": {"fedramp-20x": [{"ksi": "KSI-A", "obligation": "required"}],
                       "nist-800-53-rev5": ["ac-1"]},
    }
    det_path = tmp_path / "dets.json"
    det_path.write_text(json.dumps([det]))

    assert main(["render", str(det_path), "--format", "human"]) == 0
    assert "Fixture Capability" in capsys.readouterr().out

    idx = tmp_path / "idx.csv"
    idx.write_text("KSI_ID,Obligation\nKSI-A,required\nKSI-B,required\n")
    assert main(["report", str(idx), str(det_path)]) == 0
    assert json.loads(capsys.readouterr().out)["required_addressed"] == "1/2"


@pytest.mark.skipif(not opa_available(), reason="opa binary not installed")
def test_run_slice_end_to_end(tmp_path, capsys):
    rc = main([
        "run-slice", str(FIXTURE_SLICE), "--provider", "fixture",
        "--run-id", "demo-1", "--evidence-dir", str(tmp_path / "evidence"),
    ])
    assert rc == 0
    det = json.loads(capsys.readouterr().out)
    assert det["result"] == "pass"
    assert det["frameworks"]["nist-800-53-rev5"] == ["ac-1"]
    # the evidence chain it wrote verifies
    assert main(["verify", "fixture", "--evidence-dir", str(tmp_path / "evidence")]) == 0
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_cli.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'engine.cli'`

- [ ] **Step 4: Write the implementation**

```python
# engine/cli.py
import argparse
import json
import sys
from pathlib import Path

from engine import align as align_mod
from engine import collect as collect_mod
from engine import evaluate as eval_mod
from engine import report as report_mod
from engine.evidence import record_evidence, verify_chain
from engine.render import human as render_human
from engine.render import json as render_json
from engine.render import oscal as render_oscal
from engine.render import yaml as render_yaml
from engine.slice import load_mapping

_RENDERERS = {
    "json": render_json,
    "yaml": render_yaml,
    "oscal": render_oscal,
    "human": render_human,
}


def _run_slice(slice_dir, provider, evidence_dir, run_id):
    mapping = load_mapping(slice_dir)
    payload = collect_mod.collect(slice_dir, provider)
    record = record_evidence(mapping["capability"], provider, run_id, payload, evidence_dir)
    result = eval_mod.evaluate(Path(slice_dir) / "policy", mapping["rego_package"], payload)
    return align_mod.align(mapping, result, record)


def _load_determinations(path):
    data = json.loads(Path(path).read_text())
    return data if isinstance(data, list) else [data]


def main(argv=None):
    parser = argparse.ArgumentParser(prog="fr20x")
    sub = parser.add_subparsers(dest="cmd", required=True)

    rs = sub.add_parser("run-slice", help="collect → record → evaluate → align for one slice/provider")
    rs.add_argument("slice_dir")
    rs.add_argument("--provider", required=True)
    rs.add_argument("--run-id", required=True)
    rs.add_argument("--evidence-dir", default="evidence")

    rn = sub.add_parser("render", help="render determinations to a target format")
    rn.add_argument("determinations_json")
    rn.add_argument("--format", choices=list(_RENDERERS), required=True)

    rp = sub.add_parser("report", help="coverage + required/recommended rollup")
    rp.add_argument("ksi_index_csv")
    rp.add_argument("determinations_json")

    sy = sub.add_parser("sync", help="sync FRMR catalog from FedRAMP/docs")
    sy.add_argument("--dest", default="catalog/frmr")
    sy.add_argument("--offline-dir")

    vc = sub.add_parser("verify", help="verify a capability's evidence chain")
    vc.add_argument("capability")
    vc.add_argument("--evidence-dir", default="evidence")

    args = parser.parse_args(argv)

    if args.cmd == "run-slice":
        det = _run_slice(args.slice_dir, args.provider, args.evidence_dir, args.run_id)
        print(json.dumps(det, indent=2, sort_keys=True))
        return 0
    if args.cmd == "render":
        dets = _load_determinations(args.determinations_json)
        print(_RENDERERS[args.format].render(dets))
        return 0
    if args.cmd == "report":
        idx = report_mod.load_ksi_index(args.ksi_index_csv)
        dets = _load_determinations(args.determinations_json)
        print(json.dumps(report_mod.coverage(idx, dets), indent=2))
        return 0
    if args.cmd == "sync":
        from tools.sync import sync as do_sync
        print(json.dumps(do_sync(args.dest, args.offline_dir), indent=2))
        return 0
    if args.cmd == "verify":
        ok = verify_chain(args.capability, args.evidence_dir)
        print("OK" if ok else "TAMPERED")
        return 0 if ok else 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_cli.py -v`
Expected: PASS (2 passed; the end-to-end test is SKIPPED if opa absent).

- [ ] **Step 6: Run the full suite**

Run: `pytest -v`
Expected: all tests pass (opa-dependent ones skip cleanly if opa is not installed).

- [ ] **Step 7: Commit**

```bash
git add engine/cli.py slices/_fixture tests/test_cli.py
git -c commit.gpgsign=false commit -m "Add fr20x CLI and the _fixture smoke slice; wire pipeline end-to-end"
```

---

### Task 14: `_TEMPLATE` slice (copy-me for real slices)

**Files:**
- Create: `slices/_TEMPLATE/mapping.yaml`
- Create: `slices/_TEMPLATE/collectors/aws.py`
- Create: `slices/_TEMPLATE/policy/policy.rego`
- Create: `slices/_TEMPLATE/terraform/compliant.tf`
- Create: `slices/_TEMPLATE/terraform/noncompliant.tf`
- Create: `slices/_TEMPLATE/README.md`
- Test: `tests/test_template_slice.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_template_slice.py
from pathlib import Path

from engine.slice import load_mapping

TEMPLATE = Path(__file__).resolve().parent.parent / "slices" / "_TEMPLATE"


def test_template_mapping_validates():
    mapping = load_mapping(TEMPLATE)
    assert mapping["capability"] == "template-capability"
    assert mapping["ksis"][0]["obligation"] in ("required", "recommended")


def test_template_has_required_files():
    for rel in ["collectors/aws.py", "policy/policy.rego",
                "terraform/compliant.tf", "terraform/noncompliant.tf", "README.md"]:
        assert (TEMPLATE / rel).exists(), rel
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_template_slice.py -v`
Expected: FAIL — template files do not exist.

- [ ] **Step 3: Create `slices/_TEMPLATE/mapping.yaml`**

```yaml
# Copy this folder to slices/<your-capability>/ and edit every field below.
capability: template-capability        # lower-kebab; must match the folder name
title: Human-Readable Capability Title
ksis:                                  # the 20x KSI(s) this evidence satisfies
  - id: KSI-XXX-YYY
    obligation: required               # required (MUST) | recommended (SHOULD) — see catalog/frmr
nist_controls:                         # the Rev 5 control(s) the SAME evidence satisfies
  - ac-1
providers:                            # one collector file per provider in collectors/
  - aws
evidence_source: "what control plane / API this is pulled from"
rego_package: fr20x.template_capability   # must match the package line in policy/policy.rego
```

- [ ] **Step 4: Create `slices/_TEMPLATE/collectors/aws.py`**

```python
# Provider collector. One file per provider (aws.py, azure.py, gcp.py, okta.py, splunk.py).
#
# REQUIRED: expose collect(config) -> dict, returning a NORMALIZED payload whose shape is
# identical across every provider for this slice — so the single Rego policy can evaluate
# all of them. Do NOT leak provider-specific field names into the payload.
#
# WHAT TO EDIT FOR YOUR ENVIRONMENT:
#   - Replace the body with real calls (boto3 / Azure SDK / google-cloud / Okta REST / Splunk API).
#   - Accept connection details via `config` (region, account, tenant, token env var name, etc.).
#   - Keep the return shape stable; the Rego in policy/policy.rego depends on it.
def collect(config):
    # Example normalized shape — replace values with real queried state:
    return {
        "resource_id": config.get("resource_id", "REPLACE-ME"),
        "compliant_flag": False,  # <-- compute this from the real control-plane response
    }
```

- [ ] **Step 5: Create `slices/_TEMPLATE/policy/policy.rego`**

```rego
# Source-agnostic policy: evaluates the NORMALIZED payload from any provider collector.
# The package name MUST match `rego_package` in mapping.yaml.
package fr20x.template_capability

import rego.v1

# Add one rule per failure condition. Each adds a human-readable violation string.
violations contains msg if {
	input.compliant_flag != true
	msg := "resource is not in the compliant state"
}

# REQUIRED decision document consumed by the engine. Do not rename.
result := {"pass": count(violations) == 0, "violations": violations}
```

- [ ] **Step 6: Create `slices/_TEMPLATE/terraform/compliant.tf`**

```hcl
# Provisions the resource in a COMPLIANT state. Use this to demonstrate a passing check
# and as a reference implementation for the CSP. Replace with the real resource.
#
# WHAT TO EDIT: provider block, resource type, and the settings that make it compliant.
# terraform {
#   required_providers { aws = { source = "hashicorp/aws" } }
# }
# resource "example_resource" "compliant" {
#   secure_setting = true
# }
```

- [ ] **Step 7: Create `slices/_TEMPLATE/terraform/noncompliant.tf`**

```hcl
# A DELIBERATELY non-compliant variant, so the policy can be SEEN to catch a violation.
# Apply in a throwaway environment to prove the Rego fails as expected.
#
# WHAT TO EDIT: mirror compliant.tf but flip the setting(s) that violate the control.
# resource "example_resource" "noncompliant" {
#   secure_setting = false
# }
```

- [ ] **Step 8: Create `slices/_TEMPLATE/README.md`**

```markdown
# Slice: <capability>

> Copy this folder to `slices/<your-capability>/` and work top-to-bottom.

## What this slice proves
One sentence: the security capability, the 20x KSI(s), and the Rev 5 control(s) it satisfies.

## Files and what to edit
| File | Edit |
|---|---|
| `mapping.yaml` | KSI id(s) + obligation, NIST controls, providers, `rego_package`. |
| `collectors/<provider>.py` | `collect(config)` → normalized payload (same shape for every provider). |
| `policy/policy.rego` | One `violations` rule per failure condition; keep the `result` document. |
| `terraform/compliant.tf` | Reference compliant resource. |
| `terraform/noncompliant.tf` | Deliberately failing variant to prove the policy catches it. |

## Run it
```bash
fr20x run-slice slices/<your-capability> --provider <provider> --run-id <run-id> > det.json
fr20x render det.json --format oscal      # or json | yaml | human
fr20x verify <capability>                 # confirm the evidence chain is intact
```

## Add a Rego test
Put `policy/policy_test.rego` next to the policy and run `opa test slices/<your-capability>/policy`.
The non-compliant fixture must fail; the compliant must pass.
```

- [ ] **Step 9: Run tests to verify they pass**

Run: `pytest tests/test_template_slice.py -v`
Expected: PASS (2 passed)

- [ ] **Step 10: Commit**

```bash
git add slices/_TEMPLATE tests/test_template_slice.py
git -c commit.gpgsign=false commit -m "Add _TEMPLATE slice with edit-here guidance for new capabilities"
```

---

### Task 15: README, architecture, and onboarding docs

**Files:**
- Create: `README.md`
- Create: `docs/architecture.md`
- Create: `docs/onboarding/getting-started.md`
- Create: `docs/onboarding/anatomy-of-a-slice.md`
- Create: `docs/onboarding/adding-a-new-slice.md`
- Test: `tests/test_docs_present.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_docs_present.py
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_required_docs_exist_and_are_nonempty():
    for rel in [
        "README.md",
        "docs/architecture.md",
        "docs/onboarding/getting-started.md",
        "docs/onboarding/anatomy-of-a-slice.md",
        "docs/onboarding/adding-a-new-slice.md",
    ]:
        p = ROOT / rel
        assert p.exists(), rel
        assert len(p.read_text().strip()) > 200, f"{rel} looks like a stub"


def test_no_drafting_tool_references():
    # guard the working rule: nothing references the drafting tool
    banned = ["claude", "anthropic", "co-authored-by"]
    for p in (ROOT / "docs").rglob("*.md"):
        text = p.read_text().lower()
        for word in banned:
            assert word not in text, f"{p} contains banned reference '{word}'"
    assert "claude" not in (ROOT / "README.md").read_text().lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_docs_present.py -v`
Expected: FAIL — docs do not exist.

- [ ] **Step 3: Create `README.md`**

```markdown
# FedRAMP20x Engineering

An advisory + evidence toolkit for FedRAMP engagements. It helps the advisory team (1) guide
a client through the **Rev 5 vs. 20x** decision and run a gap assessment, and (2) produce
**timestamped, hashed, chained, machine-readable evidence** that is automatically aligned to
**both** the 20x Key Security Indicators **and** the mapped NIST 800-53 Rev 5 controls — then
rendered to OSCAL, JSON, YAML, or human-readable form.

One security fact is collected once, then aligned to every control/KSI it satisfies. The team
maintains **one slice per capability**, not one per framework.

## Why this shape
The FedRAMP PMO now expects machine-readable **and** human-readable packages for Rev 5 as well
as 20x. So evidence is framework-agnostic; only the render target changes. Evaluation is done by
OPA/Rego (no model in the decision path), so a 3PAO can re-run and get byte-identical verdicts.

## Quickstart
```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
brew install opa            # or download from the OPA releases page
pytest -v                   # run the suite
fr20x run-slice slices/_fixture --provider fixture --run-id demo-1 > det.json
fr20x render det.json --format human
fr20x verify fixture
```

## Layout
- `docs/advisory/` — the Rev 5 vs 20x decision lens (added in a later plan).
- `gap-assessment/` — how to run a 20x gap assessment + the question bank (later plan).
- `slices/` — one folder per capability (`_TEMPLATE` to copy, `_fixture` for the smoke demo).
- `engine/` — collect → record → evaluate → align → render → report.
- `tools/sync.py` — pull the latest FRMR catalog from `FedRAMP/docs`.
- `catalog/` — synced, read-only source of truth.

See `docs/architecture.md` and `docs/onboarding/`. Attribution is in `NOTICE.md`.
```

- [ ] **Step 4: Create `docs/architecture.md`**

```markdown
# Architecture

## Pipeline
```
collect → record_evidence → evaluate → align → render
  │            │               │          │        └─ oscal | json | yaml | human
  │            │               │          └─ attach the determination to all 20x KSIs + Rev 5 controls
  │            │               └─ OPA/Rego over the normalized payload → {pass, violations}
  │            └─ RFC3339 timestamp + payload sha256 + file sha256 + per-capability hash chain
  └─ per-provider collector returns a normalized payload (same shape across providers)
```

## Why each boundary exists
- **Collectors are provider-specific; the policy is not.** Each `collectors/<provider>.py`
  normalizes to one shape, so a single Rego policy evaluates AWS, Azure, GCP, Okta, or Splunk.
- **Evidence integrity is separate from evaluation.** `engine/evidence.py` is the only place
  that hashes, timestamps, and chains, so integrity rules live in one auditable module.
- **Alignment is the framework-agnostic seam.** `engine/align.py` is where one fact becomes
  evidence for both frameworks; renderers and reports never re-derive framework mappings.
- **No model in the decision path.** Evaluation is OPA/Rego; verdicts are reproducible.

## Evidence integrity
Each record stores the canonical-payload sha256; the chain log additionally stores the file's
sha256 and the prior record's hash. `fr20x verify <capability>` recomputes all three and the
chain linkage, detecting tampering, reordering, or dropped records.

## Determinism
`canonical_json` sorts keys and removes whitespace; OSCAL UUIDs are uuid5-derived. Given the same
inputs, every output is byte-identical — a property a 3PAO can rely on.
```

- [ ] **Step 5: Create `docs/onboarding/getting-started.md`**

```markdown
# Getting Started

For a new team member or a CSP engineer. Assumes Python 3.12 and git.

## 1. Install
```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
brew install opa     # macOS; otherwise download from the OPA releases page
```

## 2. Run the smoke slice
```bash
fr20x run-slice slices/_fixture --provider fixture --run-id demo-1 > det.json
cat det.json                              # one determination, aligned to a KSI + a control
fr20x render det.json --format oscal      # machine-readable; also: json | yaml | human
fr20x verify fixture                      # prints OK — the evidence chain is intact
```

## 3. Sync the catalog
```bash
fr20x sync --dest catalog/frmr            # pulls the latest FRMR files from FedRAMP/docs
```
Re-sync before every engagement so KSI IDs and obligations are current.

## 4. Run the tests
```bash
pytest -v
```
OPA-dependent tests skip automatically if `opa` is not installed; install it to run them.

## Next
Read `anatomy-of-a-slice.md`, then `adding-a-new-slice.md`.
```

- [ ] **Step 6: Create `docs/onboarding/anatomy-of-a-slice.md`**

```markdown
# Anatomy of a Slice

A slice is a self-contained vertical for one security capability:

```
slices/<capability>/
├─ mapping.yaml      # KSI(s) + obligation, NIST controls, providers, rego_package
├─ collectors/       # one file per provider; each collect(config) → NORMALIZED payload
├─ policy/           # OPA/Rego over the normalized payload → {pass, violations}
├─ terraform/        # compliant.tf + noncompliant.tf (prove the policy catches violations)
└─ README.md         # what to edit for this slice
```

## The contracts that make it work
- **Normalized payload.** Every collector for a slice returns the same shape, so one policy
  evaluates all providers. Never leak provider-specific field names into the payload.
- **Rego result document.** The policy defines `result := {"pass": <bool>, "violations": [...]}`
  under the package named in `mapping.yaml`. The engine reads exactly that.
- **One fact, both frameworks.** `mapping.yaml` lists the 20x KSI(s) and the Rev 5 control(s)
  the same evidence satisfies; `align` attaches both automatically.

## Data flow for one run
`collect` (provider → normalized JSON) → `record_evidence` (timestamp + hash + chain) →
`evaluate` (Rego → pass/fail) → `align` (→ determination with both frameworks) →
`render` (OSCAL/JSON/YAML/human). The human and machine renders come from the same
determination object, so they reconcile by construction.
```

- [ ] **Step 7: Create `docs/onboarding/adding-a-new-slice.md`**

```markdown
# Adding a New Slice

1. **Copy the template.**
   ```bash
   cp -r slices/_TEMPLATE slices/<capability>
   ```
2. **Fill `mapping.yaml`.** Set `capability` (= folder name), the KSI id(s) and each
   `obligation` (look it up in `catalog/frmr` after `fr20x sync`), the `nist_controls`, the
   `providers` list, and `rego_package`.
3. **Write the collectors.** One `collectors/<provider>.py` per provider. Each `collect(config)`
   queries the real control plane and returns the **same normalized shape**. Accept connection
   details via `config`.
4. **Write the policy.** In `policy/policy.rego`, set the package to `rego_package`, add one
   `violations` rule per failure condition, and keep the `result` document.
5. **Write Terraform.** Make `compliant.tf` and `noncompliant.tf` real; the non-compliant one
   must trip the policy.
6. **Add a Rego test.** `policy/policy_test.rego`; run `opa test slices/<capability>/policy`.
7. **Run it end to end.**
   ```bash
   fr20x run-slice slices/<capability> --provider <provider> --run-id <id> > det.json
   fr20x render det.json --format oscal
   fr20x verify <capability>
   ```
8. **Add the KSI(s)** to the gap tracker so coverage reporting counts them.
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `pytest tests/test_docs_present.py -v`
Expected: PASS (2 passed)

- [ ] **Step 9: Run the full suite once more**

Run: `pytest -v`
Expected: all pass (opa-dependent tests skip if opa absent).

- [ ] **Step 10: Commit**

```bash
git add README.md docs/architecture.md docs/onboarding tests/test_docs_present.py
git -c commit.gpgsign=false commit -m "Add README, architecture, and onboarding documentation"
```

---

## Self-review against the spec

**Spec coverage (Plan 1's portion):**
- Framework-agnostic evidence (collect once → align to both) — Tasks 5, 7, 13. ✓
- Timestamped + hashed + chained evidence — Task 3. ✓
- OPA/Rego evaluation — Tasks 6, 13, 14. ✓
- Render to OSCAL / JSON / YAML / human, reconciling — Tasks 8, 9, 10. ✓
- ≥70% coverage + required vs. recommended rollup + gap ordering — Task 11. ✓
- Sync FRMR + obligation extraction + diff — Task 12. ✓ (Rev 5 OSCAL baseline fetch is deferred — see below.)
- Runnable CLI — Task 13. ✓
- `_TEMPLATE` + customization guidance + onboarding — Tasks 14, 15. ✓
- Standalone + credit (NOTICE), no drafting-tool references, local-only commits — Tasks 0, 15, and every commit step. ✓
- Schemas (evidence/finding/slice-mapping) — Task 2. ✓

**Deferred to later plans (intentionally, not gaps):**
- `docs/advisory/*` and `gap-assessment/*` content (the refined zip material + question bank + seeded tracker) — **Plan 5 (Advisory & Gap-Assessment Docs)**.
- The three real slices `iam-mfa`, `network-restriction`, `audit-logging-siem` with full multi-cloud collectors and Rego tests — **Plans 2, 3, 4** (one per slice; each repeats the Task 14 structure with real collectors/policy/terraform).
- Rev 5 OSCAL baseline fetch in `sync.py` (FRMR/KSI obligations land here; Rev 5 baseline download is added when Plan 2 needs it, against the verified FedRAMP automation repo path).

**Placeholder scan:** No "TBD"/"implement later"/"add error handling" steps; every code step contains complete code. The `_TEMPLATE` files contain intentional `REPLACE-ME`/edit-here guidance — that is the template's purpose, asserted only for existence, never executed.

**Type/name consistency:** `record_evidence`, `EvidenceRecord.record_hash`, `verify_chain`, `evaluate(...)→{"result","violations"}`, the determination shape, `coverage(...)` keys, and `extract_obligations`/`diff_catalog`/`sync` signatures are used identically across Tasks 3–15. The Rego `result` document and the normalized-payload contract are consistent across Tasks 6, 13, 14. ✓

---

## Follow-on plans (to be written next, in order)
1. **Plan 2 — `iam-mfa` slice** (KSI-IAM-MFA / IA-2(1)(2)(8)): collectors for Okta, Entra/Azure, AWS Identity Center, GCP; shared Rego; Terraform compliant/non-compliant; Rego tests; add Rev 5 baseline fetch to sync.
2. **Plan 3 — `network-restriction` slice** (KSI-CNA-RNT / AC-17(3), SC-7(5)).
3. **Plan 4 — `audit-logging-siem` slice** (KSI-MLA-OSM / AU-2, AU-3, AU-6): CloudTrail→Splunk, Azure Monitor→Sentinel, GCP audit logs.
4. **Plan 5 — Advisory & gap-assessment docs**: refine the seed zip content into `docs/advisory/`; build `gap-assessment/` (README method, question bank by KSI theme, seeded `ksi-gap-tracker.csv` with the Obligation column).
