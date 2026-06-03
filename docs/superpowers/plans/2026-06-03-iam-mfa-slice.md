# IAM MFA Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first real evidence slice — `iam-mfa` — that proves human users are protected by **enforced, phishing-resistant MFA**, collected with parity across Okta, Microsoft Entra, AWS IAM Identity Center, and Google Workspace, evaluated by one shared Rego policy, and aligned to KSI-IAM-MFA + NIST IA-2(1)/(2)/(8). Adds the `--config` CLI flag the real collectors need and extends `tools/sync.py` to pull the Rev 5 OSCAL baselines.

**Architecture:** A new slice directory `slices/iam-mfa/` following the `slices/_TEMPLATE/` contract: one `mapping.yaml`, one **shared** `policy/policy.rego` (provider-agnostic — every collector emits the *same normalized payload shape*, so a single policy evaluates all four), one collector file per provider under `collectors/`, a Terraform compliant/non-compliant reference pair, and a README. Each collector splits a pure, unit-tested `normalize(raw) -> payload` from a `collect(config)` that lazily imports its cloud SDK — so the determinism guarantee holds (collectors are the only I/O boundary) and `normalize` is testable with captured fixtures and **no network**. Two engine-level changes support real slices: a `--config` flag on `run-slice` (passed through to the collector) and a `sync_baselines()` function in `tools/sync.py`.

**Tech Stack:** Python 3.12, pytest, PyYAML, jsonschema, Open Policy Agent (`opa` binary, `opa test` for policy unit tests). Collector SDKs are **optional extras** (`requests`, `msgraph-sdk`, `boto3`, `google-api-python-client`) lazily imported inside `collect()` only.

**Working rules (do not violate):** Commit locally only — never push or merge (the repo owner does that). Never add an AI-attribution trailer or any reference to the drafting tool in commits or content. Commit with `git -c commit.gpgsign=false commit`.

---

## Contracts this plan depends on (from Plan 1 — must match exactly)

- `engine/collect.py`: `collect(slice_dir, provider, config=None) -> dict` — loads `collectors/<provider>.py` via importlib and calls its module-level `collect(config)`. **Collectors are loaded as standalone files, NOT as a package** — a collector cannot `import` a sibling file in the same directory. Each collector must therefore be self-contained.
- `engine/evaluate.py`: `evaluate(policy_dir, rego_package, input_data) -> {"result": "pass"|"fail", "violations": [...]}`. Rego must expose `result := {"pass": bool, "violations": [...]}`.
- `engine/align.py`: reads `mapping["capability"]`, `mapping["title"]`, `mapping.get("ksis", [])` (each `{id, obligation}`), `mapping.get("nist_controls", [])`.
- `engine/cli.py`: `_run_slice(slice_dir, provider, evidence_dir, run_id)` currently passes **no** config to the collector (always `{}`). This plan adds the `--config` path.
- `schemas/slice-mapping.schema.json`: requires `capability` (pattern `^[a-z][a-z0-9-]*$`), `ksis` (each `{id, obligation∈{required,recommended}}`), `nist_controls`, `providers`, `rego_package`.
- NIST control IDs in `nist_controls` are rendered verbatim as OSCAL `control-id` (see `engine/render/oscal.py`), so use **lowercase dotted OSCAL form**: `ia-2`, `ia-2.1`, `ia-2.2`, `ia-2.8`.

## The normalized payload contract (the heart of this slice)

**Every** collector's `collect(config)` returns this exact shape. The shared Rego evaluates only this — it never sees a provider-specific field:

```json
{
  "subject_scope": "all-human-users",
  "mfa_required_by_policy": true,
  "phishing_resistant_required_by_policy": true,
  "users_evaluated": 42,
  "users_without_mfa": ["bob@example.com"],
  "users_with_non_phishing_resistant_mfa": ["carol@example.com"]
}
```

- `mfa_required_by_policy` — MFA is **enforced** by IdP policy, not merely available/enrolled (IA-2(1), IA-2(2)).
- `phishing_resistant_required_by_policy` — policy mandates phishing-resistant factors (IA-2(8)).
- `users_without_mfa` / `users_with_non_phishing_resistant_mfa` — sorted lists of human-user principal IDs (already non-secret identifiers; per-user privilege granularity and ID hashing are documented future enhancements, out of scope for v1).

Phishing-resistant factor classes (per provider, encoded as a module constant `_PHISHING_RESISTANT`):
- **Okta:** `webauthn`, `u2f` (FIDO2/security key, PIV). NOT: `sms`, `call`, `email`, `token:software:totp`, `push`, `question`.
- **Entra:** `fido2`, `windowsHelloForBusiness`, `x509Certificate`. NOT: `microsoftAuthenticator` (push), `sms`, `voice`, `softwareOath`.
- **AWS Identity Center:** `WebAuthn`. NOT: `TOTP`, `SMS`.
- **Google:** `SECURITY_KEY`. NOT: `GOOGLE_PROMPT`, `TOTP`, `SMS`, `BACKUP_CODE`.

---

### Task 0: Slice scaffold, mapping, optional-deps, README skeleton

**Files:**
- Create: `slices/iam-mfa/mapping.yaml`
- Create: `slices/iam-mfa/README.md`
- Modify: `pyproject.toml` (add collector extras)
- Test: `tests/test_iam_mfa_mapping.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_iam_mfa_mapping.py
from pathlib import Path

from engine.slice import load_mapping

SLICE = Path(__file__).resolve().parent.parent / "slices" / "iam-mfa"


def test_mapping_validates_and_targets_the_right_controls():
    m = load_mapping(SLICE)
    assert m["capability"] == "iam-mfa"
    assert m["rego_package"] == "fr20x.iam_mfa"
    assert {k["id"] for k in m["ksis"]} == {"KSI-IAM-MFA"}
    assert m["ksis"][0]["obligation"] == "required"
    assert set(m["nist_controls"]) == {"ia-2", "ia-2.1", "ia-2.2", "ia-2.8"}
    assert set(m["providers"]) == {"okta", "entra", "aws", "gcp"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_iam_mfa_mapping.py -v`
Expected: FAIL — `FileNotFoundError` on `slices/iam-mfa/mapping.yaml`.

- [ ] **Step 3: Create the slice mapping and README**

`slices/iam-mfa/mapping.yaml`:
```yaml
capability: iam-mfa
title: Phishing-Resistant Multi-Factor Authentication for Human Users
ksis:
  - id: KSI-IAM-MFA
    obligation: required
nist_controls:
  - ia-2
  - ia-2.1
  - ia-2.2
  - ia-2.8
providers:
  - okta
  - entra
  - aws
  - gcp
evidence_source: "IdP / IAM control plane (Okta API, Microsoft Graph, AWS IAM Identity Center, Google Admin SDK)"
rego_package: fr20x.iam_mfa
```

`slices/iam-mfa/README.md`:
```markdown
# Slice: iam-mfa

## What this slice proves
Every human user is protected by **enforced, phishing-resistant MFA** — satisfying
20x **KSI-IAM-MFA** and NIST **IA-2(1)/(2)/(8)** with one collected fact per provider.

## Normalized payload (identical across every provider)
| Field | Meaning |
|---|---|
| `mfa_required_by_policy` | MFA enforced by IdP policy (IA-2(1)/(2)) |
| `phishing_resistant_required_by_policy` | Policy mandates phishing-resistant factors (IA-2(8)) |
| `users_without_mfa` | Human principals with no MFA |
| `users_with_non_phishing_resistant_mfa` | Human principals on SMS/TOTP/push only |

## Run it
```bash
fr20x run-slice slices/iam-mfa --provider okta --run-id 2026-06-03-okta \
  --config my-okta.json > det.json
fr20x render det.json --format oscal
fr20x verify iam-mfa
```
`--config` is a JSON file with the provider connection details (see each collector's
docstring). For an offline dry-run, pass `{"raw": { ...normalized-shaped raw... }}`.

## Policy tests
`opa test slices/iam-mfa/policy` — the compliant fixture passes, the non-compliant fails.
```

- [ ] **Step 4: Add collector optional-dependencies to `pyproject.toml`**

In `pyproject.toml`, replace the `[project.optional-dependencies]` block with:
```toml
[project.optional-dependencies]
dev = ["pytest>=8.0"]
okta = ["requests>=2.31"]
entra = ["msgraph-sdk>=1.0"]
aws = ["boto3>=1.34"]
gcp = ["google-api-python-client>=2.0", "google-auth>=2.0"]
collectors = [
  "requests>=2.31",
  "msgraph-sdk>=1.0",
  "boto3>=1.34",
  "google-api-python-client>=2.0",
  "google-auth>=2.0",
]
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_iam_mfa_mapping.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add slices/iam-mfa/mapping.yaml slices/iam-mfa/README.md pyproject.toml tests/test_iam_mfa_mapping.py
git -c commit.gpgsign=false commit -m "Scaffold iam-mfa slice mapping, README, and collector extras"
```

---

### Task 1: `--config` flag on `run-slice` (engine change)

**Files:**
- Modify: `engine/cli.py` (`_run_slice` signature + `run-slice` parser + dispatch)
- Test: `tests/test_cli_config.py`

- [ ] **Step 1: Write the failing test**

Uses the existing `_fixture` slice, whose collector honors `config.get("enabled")`. Passing `{"enabled": false}` must flip the determination to `fail`.

```python
# tests/test_cli_config.py
import json
from pathlib import Path

import pytest

from engine.cli import main
from engine.evaluate import opa_available

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_SLICE = ROOT / "slices" / "_fixture"


@pytest.mark.skipif(not opa_available(), reason="opa binary not installed")
def test_config_file_is_passed_to_collector(tmp_path, capsys):
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({"enabled": False}))
    rc = main([
        "run-slice", str(FIXTURE_SLICE), "--provider", "fixture",
        "--run-id", "cfg-1", "--evidence-dir", str(tmp_path / "ev"),
        "--config", str(cfg),
    ])
    assert rc == 0
    det = json.loads(capsys.readouterr().out)
    assert det["result"] == "fail"  # enabled=false => fixture policy violation


def test_missing_config_file_is_a_clean_error(tmp_path, capsys):
    rc = main([
        "run-slice", str(FIXTURE_SLICE), "--provider", "fixture",
        "--run-id", "x", "--evidence-dir", str(tmp_path / "ev"),
        "--config", str(tmp_path / "nope.json"),
    ])
    assert rc == 1
    assert "fr20x: error:" in capsys.readouterr().err
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli_config.py -v`
Expected: FAIL — `run-slice` has no `--config` argument (`SystemExit: 2`).

- [ ] **Step 3: Implement the `--config` flag**

In `engine/cli.py`, change `_run_slice` to accept and forward config:
```python
def _run_slice(slice_dir, provider, evidence_dir, run_id, config=None):
    mapping = load_mapping(slice_dir)
    payload = collect_mod.collect(slice_dir, provider, config or {})
    record = record_evidence(mapping["capability"], provider, run_id, payload, evidence_dir)
    result = eval_mod.evaluate(Path(slice_dir) / "policy", mapping["rego_package"], payload)
    return align_mod.align(mapping, result, record)
```

Add the argument to the `run-slice` parser (after `--evidence-dir`):
```python
    rs.add_argument("--config", help="path to a JSON file passed to the collector")
```

Update the `run-slice` dispatch branch in `_dispatch`:
```python
    if args.cmd == "run-slice":
        config = json.loads(Path(args.config).read_text()) if args.config else None
        det = _run_slice(args.slice_dir, args.provider, args.evidence_dir, args.run_id, config)
        print(json.dumps(det, indent=2, sort_keys=True))
        return 0
```

(`FileNotFoundError` and `json.JSONDecodeError` are already in `_USER_ERRORS`, so a bad path/JSON yields the clean `fr20x: error:` message and exit 1.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli_config.py tests/test_cli.py -v`
Expected: PASS (config test SKIPS if opa absent; the missing-file test always runs).

- [ ] **Step 5: Commit**

```bash
git add engine/cli.py tests/test_cli_config.py
git -c commit.gpgsign=false commit -m "Add --config flag to run-slice, forwarded to the collector"
```

---

### Task 2: Shared Rego policy + `opa test`

**Files:**
- Create: `slices/iam-mfa/policy/policy.rego`
- Create: `slices/iam-mfa/policy/policy_test.rego`
- Test: `tests/test_iam_mfa_policy.py`

- [ ] **Step 1: Write the policy and its Rego unit tests**

`slices/iam-mfa/policy/policy.rego`:
```rego
# Provider-agnostic MFA policy. Evaluates the normalized payload emitted identically
# by every collector in collectors/. Package MUST match mapping.yaml `rego_package`.
package fr20x.iam_mfa

import rego.v1

violations contains msg if {
	input.mfa_required_by_policy != true
	msg := "MFA is not enforced by policy for human users (IA-2(1)/(2))"
}

violations contains msg if {
	input.phishing_resistant_required_by_policy != true
	msg := "policy does not require phishing-resistant MFA (IA-2(8))"
}

violations contains msg if {
	count(input.users_without_mfa) > 0
	msg := sprintf("%d human user(s) without any MFA: %v", [count(input.users_without_mfa), input.users_without_mfa])
}

violations contains msg if {
	count(input.users_with_non_phishing_resistant_mfa) > 0
	msg := sprintf("%d human user(s) using non-phishing-resistant MFA: %v", [count(input.users_with_non_phishing_resistant_mfa), input.users_with_non_phishing_resistant_mfa])
}

# REQUIRED decision document consumed by the engine. Do not rename.
result := {"pass": count(violations) == 0, "violations": violations}
```

`slices/iam-mfa/policy/policy_test.rego`:
```rego
package fr20x.iam_mfa_test

import rego.v1

import data.fr20x.iam_mfa

compliant := {
	"subject_scope": "all-human-users",
	"mfa_required_by_policy": true,
	"phishing_resistant_required_by_policy": true,
	"users_evaluated": 3,
	"users_without_mfa": [],
	"users_with_non_phishing_resistant_mfa": [],
}

noncompliant := {
	"subject_scope": "all-human-users",
	"mfa_required_by_policy": false,
	"phishing_resistant_required_by_policy": false,
	"users_evaluated": 3,
	"users_without_mfa": ["bob@example.com"],
	"users_with_non_phishing_resistant_mfa": ["carol@example.com"],
}

test_compliant_passes if {
	iam_mfa.result.pass with input as compliant
}

test_noncompliant_fails if {
	not iam_mfa.result.pass with input as noncompliant
}

test_all_four_violations_fire if {
	count(iam_mfa.result.violations) == 4 with input as noncompliant
}
```

- [ ] **Step 2: Run the Rego tests to verify they pass**

Run: `opa test slices/iam-mfa/policy -v`
Expected: `PASS: 3/3` (`test_compliant_passes`, `test_noncompliant_fails`, `test_all_four_violations_fire`).

- [ ] **Step 3: Write the pytest wrapper that runs `opa test` in CI**

```python
# tests/test_iam_mfa_policy.py
import subprocess
from pathlib import Path

import pytest

from engine.evaluate import opa_available

POLICY_DIR = Path(__file__).resolve().parent.parent / "slices" / "iam-mfa" / "policy"


@pytest.mark.skipif(not opa_available(), reason="opa binary not installed")
def test_opa_unit_tests_pass():
    proc = subprocess.run(
        ["opa", "test", str(POLICY_DIR)],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
```

- [ ] **Step 4: Run it**

Run: `pytest tests/test_iam_mfa_policy.py -v`
Expected: PASS (SKIPS if opa absent).

- [ ] **Step 5: Commit**

```bash
git add slices/iam-mfa/policy tests/test_iam_mfa_policy.py
git -c commit.gpgsign=false commit -m "Add shared iam-mfa Rego policy with opa unit tests"
```

---

### Task 3: Okta collector

**Files:**
- Create: `slices/iam-mfa/collectors/okta.py`
- Test: `tests/test_iam_mfa_okta.py`

The collector splits a pure `normalize(raw)` (tested here) from `collect(config)` (lazy `requests`). `collect` also honors an offline `config["raw"]` seam so a dry-run / the end-to-end engine test needs no network.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_iam_mfa_okta.py
import importlib.util
from pathlib import Path

COLLECTOR = Path(__file__).resolve().parent.parent / "slices" / "iam-mfa" / "collectors" / "okta.py"


def _load():
    spec = importlib.util.spec_from_file_location("okta_collector", COLLECTOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_normalize_classifies_factors_and_policy():
    okta = _load()
    raw = {
        "policy": {"mfa_required": True, "phishing_resistant_required": True},
        "users": [
            {"id": "alice@x", "status": "ACTIVE", "type": "human", "factors": ["webauthn"]},
            {"id": "bob@x", "status": "ACTIVE", "type": "human", "factors": []},
            {"id": "carol@x", "status": "ACTIVE", "type": "human", "factors": ["sms", "push"]},
            {"id": "svc@x", "status": "ACTIVE", "type": "service", "factors": []},
            {"id": "old@x", "status": "DEPROVISIONED", "type": "human", "factors": []},
        ],
    }
    out = okta.normalize(raw)
    assert out["subject_scope"] == "all-human-users"
    assert out["mfa_required_by_policy"] is True
    assert out["phishing_resistant_required_by_policy"] is True
    assert out["users_evaluated"] == 3            # service + deprovisioned excluded
    assert out["users_without_mfa"] == ["bob@x"]
    assert out["users_with_non_phishing_resistant_mfa"] == ["carol@x"]


def test_collect_uses_offline_raw_seam():
    okta = _load()
    out = okta.collect({"raw": {
        "policy": {"mfa_required": True, "phishing_resistant_required": True},
        "users": [{"id": "a@x", "status": "ACTIVE", "type": "human", "factors": ["webauthn"]}],
    }})
    assert out["users_without_mfa"] == []
    assert out["users_evaluated"] == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_iam_mfa_okta.py -v`
Expected: FAIL — collector file does not exist.

- [ ] **Step 3: Write the collector**

`slices/iam-mfa/collectors/okta.py`:
```python
# Okta collector for the iam-mfa slice.
#
# Returns the normalized payload shared by every iam-mfa collector. `normalize(raw)`
# is pure and unit-tested; `collect(config)` does the live Okta REST calls (lazy
# `requests` import) and then normalizes. Pass {"raw": {...}} in config for an
# offline dry-run.
#
# config (live mode):
#   {"okta_domain": "example.okta.com", "token_env": "OKTA_API_TOKEN"}
# A user's "factors" is the list of enrolled Okta factorType strings.

_PHISHING_RESISTANT = {"webauthn", "u2f"}


def normalize(raw):
    users = [
        u for u in raw.get("users", [])
        if u.get("type", "human") == "human"
        and str(u.get("status", "ACTIVE")).upper() == "ACTIVE"
    ]
    without, weak = [], []
    for u in users:
        factors = u.get("factors", [])
        if not factors:
            without.append(u["id"])
        elif not any(f in _PHISHING_RESISTANT for f in factors):
            weak.append(u["id"])
    pol = raw.get("policy", {})
    return {
        "subject_scope": "all-human-users",
        "mfa_required_by_policy": bool(pol.get("mfa_required", False)),
        "phishing_resistant_required_by_policy": bool(pol.get("phishing_resistant_required", False)),
        "users_evaluated": len(users),
        "users_without_mfa": sorted(without),
        "users_with_non_phishing_resistant_mfa": sorted(weak),
    }


def collect(config):
    if "raw" in config:
        return normalize(config["raw"])
    import os

    import requests  # optional dep: pip install '.[okta]'

    domain = config["okta_domain"]
    token = os.environ[config.get("token_env", "OKTA_API_TOKEN")]
    headers = {"Authorization": f"SSWS {token}", "Accept": "application/json"}
    base = f"https://{domain}/api/v1"

    users = []
    url = f"{base}/users?filter=status eq \"ACTIVE\"&limit=200"
    while url:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        for u in resp.json():
            f = requests.get(f"{base}/users/{u['id']}/factors", headers=headers, timeout=30)
            f.raise_for_status()
            users.append({
                "id": u["profile"].get("login", u["id"]),
                "status": u["status"],
                "type": "human",
                "factors": [fac["factorType"] for fac in f.json()],
            })
        url = resp.links.get("next", {}).get("url")

    # Policy enforcement is supplied via config (derive from your Okta global session
    # / authenticator enrollment policy); Okta's API does not expose a single boolean.
    pol = config.get("policy", {"mfa_required": False, "phishing_resistant_required": False})
    return normalize({"policy": pol, "users": users})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_iam_mfa_okta.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add slices/iam-mfa/collectors/okta.py tests/test_iam_mfa_okta.py
git -c commit.gpgsign=false commit -m "Add Okta collector for the iam-mfa slice"
```

---

### Task 4: Microsoft Entra collector

**Files:**
- Create: `slices/iam-mfa/collectors/entra.py`
- Test: `tests/test_iam_mfa_entra.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_iam_mfa_entra.py
import importlib.util
from pathlib import Path

COLLECTOR = Path(__file__).resolve().parent.parent / "slices" / "iam-mfa" / "collectors" / "entra.py"


def _load():
    spec = importlib.util.spec_from_file_location("entra_collector", COLLECTOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_normalize_classifies_entra_methods():
    entra = _load()
    raw = {
        "policy": {"mfa_required": True, "phishing_resistant_required": False},
        "users": [
            {"id": "alice@x", "status": "ACTIVE", "type": "human", "factors": ["fido2"]},
            {"id": "bob@x", "status": "ACTIVE", "type": "human", "factors": ["microsoftAuthenticator"]},
            {"id": "dan@x", "status": "ACTIVE", "type": "human", "factors": []},
            {"id": "guest@x", "status": "ACTIVE", "type": "guest", "factors": []},
        ],
    }
    out = entra.normalize(raw)
    assert out["mfa_required_by_policy"] is True
    assert out["phishing_resistant_required_by_policy"] is False
    assert out["users_evaluated"] == 3                       # guest excluded
    assert out["users_without_mfa"] == ["dan@x"]
    assert out["users_with_non_phishing_resistant_mfa"] == ["bob@x"]


def test_collect_uses_offline_raw_seam():
    entra = _load()
    out = entra.collect({"raw": {
        "policy": {"mfa_required": True, "phishing_resistant_required": True},
        "users": [{"id": "a@x", "status": "ACTIVE", "type": "human", "factors": ["windowsHelloForBusiness"]}],
    }})
    assert out["users_with_non_phishing_resistant_mfa"] == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_iam_mfa_entra.py -v`
Expected: FAIL — collector file does not exist.

- [ ] **Step 3: Write the collector**

`slices/iam-mfa/collectors/entra.py`:
```python
# Microsoft Entra (Azure AD) collector for the iam-mfa slice.
#
# `normalize(raw)` is pure and unit-tested. `collect(config)` calls Microsoft Graph
# (lazy `msgraph-sdk`). Pass {"raw": {...}} for an offline dry-run.
#
# config (live mode):
#   {"tenant_id": "...", "client_id": "...", "client_secret_env": "ENTRA_CLIENT_SECRET"}
# "factors" holds Graph authentication-method @odata.type short names.
# Only "human" members are evaluated; guests are excluded.

_PHISHING_RESISTANT = {"fido2", "windowsHelloForBusiness", "x509Certificate"}


def normalize(raw):
    users = [
        u for u in raw.get("users", [])
        if u.get("type", "human") == "human"
        and str(u.get("status", "ACTIVE")).upper() == "ACTIVE"
    ]
    without, weak = [], []
    for u in users:
        factors = u.get("factors", [])
        if not factors:
            without.append(u["id"])
        elif not any(f in _PHISHING_RESISTANT for f in factors):
            weak.append(u["id"])
    pol = raw.get("policy", {})
    return {
        "subject_scope": "all-human-users",
        "mfa_required_by_policy": bool(pol.get("mfa_required", False)),
        "phishing_resistant_required_by_policy": bool(pol.get("phishing_resistant_required", False)),
        "users_evaluated": len(users),
        "users_without_mfa": sorted(without),
        "users_with_non_phishing_resistant_mfa": sorted(weak),
    }


def collect(config):
    if "raw" in config:
        return normalize(config["raw"])
    import asyncio
    import os

    from azure.identity import ClientSecretCredential  # optional dep: pip install '.[entra]'
    from msgraph import GraphServiceClient

    cred = ClientSecretCredential(
        tenant_id=config["tenant_id"],
        client_id=config["client_id"],
        client_secret=os.environ[config.get("client_secret_env", "ENTRA_CLIENT_SECRET")],
    )
    client = GraphServiceClient(cred)

    async def _gather():
        rows = []
        users = await client.users.get()
        for u in users.value:
            if u.user_type and u.user_type.lower() == "guest":
                continue
            methods = await client.users.by_user_id(u.id).authentication.methods.get()
            factors = [
                (m.odata_type or "").rsplit(".", 1)[-1].replace("AuthenticationMethod", "")
                for m in methods.value
            ]
            rows.append({
                "id": u.user_principal_name or u.id,
                "status": "ACTIVE" if (u.account_enabled is not False) else "DISABLED",
                "type": "human",
                "factors": [f for f in factors if f],
            })
        return rows

    users = asyncio.run(_gather())
    pol = config.get("policy", {"mfa_required": False, "phishing_resistant_required": False})
    return normalize({"policy": pol, "users": users})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_iam_mfa_entra.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add slices/iam-mfa/collectors/entra.py tests/test_iam_mfa_entra.py
git -c commit.gpgsign=false commit -m "Add Microsoft Entra collector for the iam-mfa slice"
```

---

### Task 5: AWS IAM Identity Center collector

**Files:**
- Create: `slices/iam-mfa/collectors/aws.py`
- Test: `tests/test_iam_mfa_aws.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_iam_mfa_aws.py
import importlib.util
from pathlib import Path

COLLECTOR = Path(__file__).resolve().parent.parent / "slices" / "iam-mfa" / "collectors" / "aws.py"


def _load():
    spec = importlib.util.spec_from_file_location("aws_collector", COLLECTOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_normalize_classifies_aws_devices():
    aws = _load()
    raw = {
        "policy": {"mfa_required": True, "phishing_resistant_required": True},
        "users": [
            {"id": "alice", "status": "ACTIVE", "type": "human", "factors": ["WebAuthn"]},
            {"id": "bob", "status": "ACTIVE", "type": "human", "factors": ["TOTP"]},
            {"id": "carol", "status": "ACTIVE", "type": "human", "factors": []},
        ],
    }
    out = aws.normalize(raw)
    assert out["users_evaluated"] == 3
    assert out["users_without_mfa"] == ["carol"]
    assert out["users_with_non_phishing_resistant_mfa"] == ["bob"]


def test_collect_uses_offline_raw_seam():
    aws = _load()
    out = aws.collect({"raw": {
        "policy": {"mfa_required": True, "phishing_resistant_required": True},
        "users": [{"id": "a", "status": "ACTIVE", "type": "human", "factors": ["WebAuthn"]}],
    }})
    assert out["users_without_mfa"] == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_iam_mfa_aws.py -v`
Expected: FAIL — collector file does not exist.

- [ ] **Step 3: Write the collector**

`slices/iam-mfa/collectors/aws.py`:
```python
# AWS IAM Identity Center collector for the iam-mfa slice.
#
# `normalize(raw)` is pure and unit-tested. `collect(config)` queries Identity Store
# (lazy `boto3`). Pass {"raw": {...}} for an offline dry-run.
#
# config (live mode):
#   {"identity_store_id": "d-1234567890", "region": "us-gov-west-1"}
# "factors" holds Identity Center MFA device types (e.g. "WebAuthn", "TOTP", "SMS").

_PHISHING_RESISTANT = {"WebAuthn"}


def normalize(raw):
    users = [
        u for u in raw.get("users", [])
        if u.get("type", "human") == "human"
        and str(u.get("status", "ACTIVE")).upper() == "ACTIVE"
    ]
    without, weak = [], []
    for u in users:
        factors = u.get("factors", [])
        if not factors:
            without.append(u["id"])
        elif not any(f in _PHISHING_RESISTANT for f in factors):
            weak.append(u["id"])
    pol = raw.get("policy", {})
    return {
        "subject_scope": "all-human-users",
        "mfa_required_by_policy": bool(pol.get("mfa_required", False)),
        "phishing_resistant_required_by_policy": bool(pol.get("phishing_resistant_required", False)),
        "users_evaluated": len(users),
        "users_without_mfa": sorted(without),
        "users_with_non_phishing_resistant_mfa": sorted(weak),
    }


def collect(config):
    if "raw" in config:
        return normalize(config["raw"])
    import boto3  # optional dep: pip install '.[aws]'

    store_id = config["identity_store_id"]
    ids = boto3.client("identitystore", region_name=config.get("region"))

    users = []
    paginator = ids.get_paginator("list_users")
    for page in paginator.paginate(IdentityStoreId=store_id):
        for u in page["Users"]:
            devices = ids.list_mfa_devices(
                IdentityStoreId=store_id, MemberId={"UserId": u["UserId"]}
            ).get("MFADevices", [])
            users.append({
                "id": u.get("UserName", u["UserId"]),
                "status": "ACTIVE",
                "type": "human",
                "factors": [d.get("DeviceType", "Unknown") for d in devices],
            })

    pol = config.get("policy", {"mfa_required": False, "phishing_resistant_required": False})
    return normalize({"policy": pol, "users": users})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_iam_mfa_aws.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add slices/iam-mfa/collectors/aws.py tests/test_iam_mfa_aws.py
git -c commit.gpgsign=false commit -m "Add AWS IAM Identity Center collector for the iam-mfa slice"
```

---

### Task 6: Google Workspace collector

**Files:**
- Create: `slices/iam-mfa/collectors/gcp.py`
- Test: `tests/test_iam_mfa_gcp.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_iam_mfa_gcp.py
import importlib.util
from pathlib import Path

COLLECTOR = Path(__file__).resolve().parent.parent / "slices" / "iam-mfa" / "collectors" / "gcp.py"


def _load():
    spec = importlib.util.spec_from_file_location("gcp_collector", COLLECTOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_normalize_classifies_google_2sv():
    gcp = _load()
    raw = {
        "policy": {"mfa_required": True, "phishing_resistant_required": True},
        "users": [
            {"id": "alice@x", "status": "ACTIVE", "type": "human", "factors": ["SECURITY_KEY"]},
            {"id": "bob@x", "status": "ACTIVE", "type": "human", "factors": ["GOOGLE_PROMPT"]},
            {"id": "carol@x", "status": "ACTIVE", "type": "human", "factors": []},
        ],
    }
    out = gcp.normalize(raw)
    assert out["users_evaluated"] == 3
    assert out["users_without_mfa"] == ["carol@x"]
    assert out["users_with_non_phishing_resistant_mfa"] == ["bob@x"]


def test_collect_uses_offline_raw_seam():
    gcp = _load()
    out = gcp.collect({"raw": {
        "policy": {"mfa_required": True, "phishing_resistant_required": True},
        "users": [{"id": "a@x", "status": "ACTIVE", "type": "human", "factors": ["SECURITY_KEY"]}],
    }})
    assert out["users_with_non_phishing_resistant_mfa"] == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_iam_mfa_gcp.py -v`
Expected: FAIL — collector file does not exist.

- [ ] **Step 3: Write the collector**

`slices/iam-mfa/collectors/gcp.py`:
```python
# Google Workspace collector for the iam-mfa slice.
#
# `normalize(raw)` is pure and unit-tested. `collect(config)` calls the Admin SDK
# Directory API (lazy google-api-python-client). Pass {"raw": {...}} for an offline
# dry-run.
#
# config (live mode):
#   {"customer": "my_customer", "delegated_admin": "admin@example.com",
#    "sa_key_env": "GOOGLE_SA_KEY_FILE"}
# "factors" is derived per user: SECURITY_KEY when a hardware key is enrolled,
# else the weakest enrolled 2SV method (GOOGLE_PROMPT / TOTP / SMS / BACKUP_CODE).

_PHISHING_RESISTANT = {"SECURITY_KEY"}


def normalize(raw):
    users = [
        u for u in raw.get("users", [])
        if u.get("type", "human") == "human"
        and str(u.get("status", "ACTIVE")).upper() == "ACTIVE"
    ]
    without, weak = [], []
    for u in users:
        factors = u.get("factors", [])
        if not factors:
            without.append(u["id"])
        elif not any(f in _PHISHING_RESISTANT for f in factors):
            weak.append(u["id"])
    pol = raw.get("policy", {})
    return {
        "subject_scope": "all-human-users",
        "mfa_required_by_policy": bool(pol.get("mfa_required", False)),
        "phishing_resistant_required_by_policy": bool(pol.get("phishing_resistant_required", False)),
        "users_evaluated": len(users),
        "users_without_mfa": sorted(without),
        "users_with_non_phishing_resistant_mfa": sorted(weak),
    }


def collect(config):
    if "raw" in config:
        return normalize(config["raw"])
    import os

    from google.oauth2 import service_account  # optional dep: pip install '.[gcp]'
    from googleapiclient.discovery import build

    creds = service_account.Credentials.from_service_account_file(
        os.environ[config.get("sa_key_env", "GOOGLE_SA_KEY_FILE")],
        scopes=["https://www.googleapis.com/auth/admin.directory.user.readonly"],
        subject=config["delegated_admin"],
    )
    service = build("admin", "directory_v1", credentials=creds)

    users = []
    page_token = None
    while True:
        resp = service.users().list(
            customer=config.get("customer", "my_customer"),
            maxResults=200, pageToken=page_token, projection="full",
        ).execute()
        for u in resp.get("users", []):
            if not u.get("isEnrolledIn2Sv"):
                factors = []
            elif u.get("isEnforcedIn2Sv"):
                # Admin SDK does not expose the exact 2SV factor; security-key
                # enforcement is supplied via config.security_key_users allowlist.
                factors = ["SECURITY_KEY"] if u.get("primaryEmail") in config.get(
                    "security_key_users", []) else ["GOOGLE_PROMPT"]
            else:
                factors = ["GOOGLE_PROMPT"]
            users.append({
                "id": u["primaryEmail"],
                "status": "ACTIVE" if not u.get("suspended") else "SUSPENDED",
                "type": "human",
                "factors": factors,
            })
        page_token = resp.get("nextPageToken")
        if not page_token:
            break

    pol = config.get("policy", {"mfa_required": False, "phishing_resistant_required": False})
    return normalize({"policy": pol, "users": users})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_iam_mfa_gcp.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add slices/iam-mfa/collectors/gcp.py tests/test_iam_mfa_gcp.py
git -c commit.gpgsign=false commit -m "Add Google Workspace collector for the iam-mfa slice"
```

---

### Task 7: Cross-provider parity + end-to-end through the engine

**Files:**
- Test: `tests/test_iam_mfa_e2e.py`

Proves (a) all four collectors emit the identical payload shape, and (b) the full engine pipeline (`run-slice` → record → evaluate → align → verify) runs through the `--config` offline `raw` seam and aligns to the right frameworks.

- [ ] **Step 1: Write the test**

```python
# tests/test_iam_mfa_e2e.py
import importlib.util
import json
from pathlib import Path

import pytest

from engine.cli import main
from engine.evaluate import opa_available

ROOT = Path(__file__).resolve().parent.parent
SLICE = ROOT / "slices" / "iam-mfa"
PROVIDERS = ["okta", "entra", "aws", "gcp"]
PAYLOAD_KEYS = {
    "subject_scope", "mfa_required_by_policy", "phishing_resistant_required_by_policy",
    "users_evaluated", "users_without_mfa", "users_with_non_phishing_resistant_mfa",
}

COMPLIANT_RAW = {
    "policy": {"mfa_required": True, "phishing_resistant_required": True},
    "users": [{"id": "a@x", "status": "ACTIVE", "type": "human", "factors": ["webauthn"]}],
}


def _load(provider):
    path = SLICE / "collectors" / f"{provider}.py"
    spec = importlib.util.spec_from_file_location(f"{provider}_c", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("provider", PROVIDERS)
def test_all_providers_emit_the_same_shape(provider):
    out = _load(provider).collect({"raw": COMPLIANT_RAW})
    assert set(out.keys()) == PAYLOAD_KEYS


@pytest.mark.skipif(not opa_available(), reason="opa binary not installed")
def test_pipeline_end_to_end_via_config(tmp_path, capsys):
    cfg = tmp_path / "okta.json"
    cfg.write_text(json.dumps({"raw": COMPLIANT_RAW}))
    rc = main([
        "run-slice", str(SLICE), "--provider", "okta", "--run-id", "e2e-1",
        "--evidence-dir", str(tmp_path / "ev"), "--config", str(cfg),
    ])
    assert rc == 0
    det = json.loads(capsys.readouterr().out)
    assert det["capability"] == "iam-mfa"
    assert det["result"] == "pass"
    assert det["frameworks"]["nist-800-53-rev5"] == ["ia-2", "ia-2.1", "ia-2.2", "ia-2.8"]
    assert det["frameworks"]["fedramp-20x"][0]["ksi"] == "KSI-IAM-MFA"
    assert main(["verify", "iam-mfa", "--evidence-dir", str(tmp_path / "ev")]) == 0
```

- [ ] **Step 2: Run the tests**

Run: `pytest tests/test_iam_mfa_e2e.py -v`
Expected: PASS (4 parity cases always run; the end-to-end case SKIPS if opa absent).

- [ ] **Step 3: Commit**

```bash
git add tests/test_iam_mfa_e2e.py
git -c commit.gpgsign=false commit -m "Add cross-provider parity and end-to-end tests for iam-mfa"
```

---

### Task 8: Sync Rev 5 OSCAL baselines

**Files:**
- Modify: `tools/sync.py` (add `BASELINE_*` constants + `sync_baselines()`)
- Modify: `engine/cli.py` (`sync --baselines` flag)
- Test: `tests/test_sync_baselines.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_sync_baselines.py
from pathlib import Path

from tools.sync import BASELINE_FILES, sync_baselines


def test_sync_baselines_offline(tmp_path):
    offline = tmp_path / "src"
    offline.mkdir()
    name = BASELINE_FILES[0]
    (offline / name).write_text('{"profile": {}}')
    dest = tmp_path / "catalog" / "baselines"

    result = sync_baselines(str(dest), offline_dir=str(offline))

    assert name in result["written"]
    assert (dest / name).exists()
    # files absent from offline_dir are skipped, not failed
    assert result["failed"] == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_sync_baselines.py -v`
Expected: FAIL — `ImportError: cannot import name 'sync_baselines'`.

- [ ] **Step 3: Add `sync_baselines` to `tools/sync.py`**

Append to `tools/sync.py` (reuses the module-level `_fetch` and `FETCH_TIMEOUT`):
```python
# Rev 5 OSCAL baseline profiles (GSA/fedramp-automation). Verify these paths against
# the live repo on first online sync — the dist layout has changed across releases.
BASELINE_BASE = (
    "https://raw.githubusercontent.com/GSA/fedramp-automation/master/"
    "dist/content/rev5/baselines/json/"
)
BASELINE_FILES = [
    "FedRAMP_rev5_LOW-baseline_profile.json",
    "FedRAMP_rev5_MODERATE-baseline_profile.json",
    "FedRAMP_rev5_HIGH-baseline_profile.json",
    "FedRAMP_rev5_LI-SaaS-baseline_profile.json",
]


def sync_baselines(dest, offline_dir=None) -> dict:
    """Sync Rev 5 OSCAL baseline profiles into dest.

    Same contract as sync(): returns {"written": {name: bytes}, "failed": {name: err}}.
    Online fetch failures are recorded under "failed" without aborting; in offline
    mode, files absent from offline_dir are skipped silently.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    written, failed = {}, {}
    for fname in BASELINE_FILES:
        try:
            if offline_dir is not None:
                source = Path(offline_dir) / fname
                if not source.exists():
                    continue
                content = source.read_text()
            else:
                content = _fetch(BASELINE_BASE + fname)
        except (urllib.error.URLError, OSError) as exc:
            failed[fname] = str(exc)
            continue
        (dest / fname).write_text(content)
        written[fname] = len(content)
    return {"written": written, "failed": failed}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_sync_baselines.py -v`
Expected: PASS.

- [ ] **Step 5: Wire the `--baselines` flag into the `sync` subcommand**

In `engine/cli.py`, add to the `sync` parser (after `--offline-dir`):
```python
    sy.add_argument("--baselines", action="store_true",
                    help="also sync Rev 5 OSCAL baseline profiles into catalog/baselines")
    sy.add_argument("--baselines-dest", default="catalog/baselines")
```

Replace the `sync` dispatch branch in `_dispatch`:
```python
    if args.cmd == "sync":
        from tools.sync import sync as do_sync
        out = {"frmr": do_sync(args.dest, args.offline_dir)}
        if args.baselines:
            from tools.sync import sync_baselines
            out["baselines"] = sync_baselines(args.baselines_dest, args.offline_dir)
        print(json.dumps(out, indent=2))
        return 0
```

- [ ] **Step 6: Run the sync tests**

Run: `pytest tests/test_sync.py tests/test_sync_baselines.py -v`
Expected: PASS (existing `test_sync.py` still green — `sync()` is unchanged).

- [ ] **Step 7: Commit**

```bash
git add tools/sync.py engine/cli.py tests/test_sync_baselines.py
git -c commit.gpgsign=false commit -m "Sync Rev 5 OSCAL baselines; add sync --baselines flag"
```

---

### Task 9: Terraform reference pair + finalize docs

**Files:**
- Create: `slices/iam-mfa/terraform/compliant.tf`
- Create: `slices/iam-mfa/terraform/noncompliant.tf`
- Modify: `slices/iam-mfa/README.md` (add Terraform + per-provider config section)
- Test: `tests/test_iam_mfa_files.py`

The reference pair is AWS (most concrete IaC for MFA enforcement); the per-provider config lives in each collector docstring. Provider-specific Terraform for Entra/GCP/Okta is a documented follow-on.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_iam_mfa_files.py
from pathlib import Path

SLICE = Path(__file__).resolve().parent.parent / "slices" / "iam-mfa"


def test_slice_has_all_required_files():
    required = [
        "mapping.yaml", "README.md",
        "policy/policy.rego", "policy/policy_test.rego",
        "collectors/okta.py", "collectors/entra.py",
        "collectors/aws.py", "collectors/gcp.py",
        "terraform/compliant.tf", "terraform/noncompliant.tf",
    ]
    for rel in required:
        assert (SLICE / rel).exists(), rel
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_iam_mfa_files.py -v`
Expected: FAIL — terraform files missing.

- [ ] **Step 3: Write the Terraform reference pair**

`slices/iam-mfa/terraform/compliant.tf`:
```hcl
# COMPLIANT reference: deny all IAM actions unless MFA is present, for the human group.
# Phishing-resistant enrollment (security keys) is an operational step layered on top;
# this Terraform proves MFA is *enforced by policy*, which the collector reports as
# mfa_required_by_policy = true.
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

resource "aws_iam_group" "humans" {
  name = "humans"
}

resource "aws_iam_group_policy" "require_mfa" {
  name  = "require-mfa"
  group = aws_iam_group.humans.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyAllExceptWithoutMFA"
      Effect    = "Deny"
      NotAction = ["iam:CreateVirtualMFADevice", "iam:EnableMFADevice", "sts:GetSessionToken"]
      Resource  = "*"
      Condition = { BoolIfExists = { "aws:MultiFactorAuthPresent" = "false" } }
    }]
  })
}
```

`slices/iam-mfa/terraform/noncompliant.tf`:
```hcl
# NON-COMPLIANT variant: the same group with NO MFA-enforcing policy, so the collector
# reports mfa_required_by_policy = false and the Rego fails. Apply only in a throwaway
# account to demonstrate the policy catches the gap.
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

resource "aws_iam_group" "humans_insecure" {
  name = "humans-insecure"
}
# (intentionally no aws_iam_group_policy requiring MFA)
```

- [ ] **Step 4: Append the Terraform + config section to the slice README**

Append to `slices/iam-mfa/README.md`:
```markdown

## Terraform reference
- `terraform/compliant.tf` — IAM group that denies actions without MFA present.
- `terraform/noncompliant.tf` — same group without the MFA condition (policy fails).
Apply the non-compliant variant in a throwaway account to prove the Rego catches it.
Per-provider Terraform for Entra/Okta/Google is a documented follow-on.

## Per-provider `--config`
| Provider | Required config keys |
|---|---|
| `okta` | `okta_domain`, `token_env`, `policy` |
| `entra` | `tenant_id`, `client_id`, `client_secret_env`, `policy` |
| `aws` | `identity_store_id`, `region`, `policy` |
| `gcp` | `customer`, `delegated_admin`, `sa_key_env`, `security_key_users`, `policy` |
Every provider also accepts `{"raw": {...}}` for an offline dry-run (no network).
```

- [ ] **Step 5: Run the file-presence test**

Run: `pytest tests/test_iam_mfa_files.py -v`
Expected: PASS.

- [ ] **Step 6: Run the full suite**

Run: `pytest -v`
Expected: all tests pass (opa-dependent and network-dependent ones skip cleanly when their tool/credentials are absent).

- [ ] **Step 7: Commit**

```bash
git add slices/iam-mfa/terraform slices/iam-mfa/README.md tests/test_iam_mfa_files.py
git -c commit.gpgsign=false commit -m "Add iam-mfa Terraform reference pair and finalize slice docs"
```

---

## Self-Review

**Spec coverage (against Plan 2 scope in the project record):**
- Real collectors Okta / Entra / AWS Identity Center / GCP → Tasks 3–6. ✅
- Shared Rego → Task 2 (one policy, provider-agnostic payload contract). ✅
- Compliant / non-compliant Terraform → Task 9. ✅
- `opa test` → Task 2 (`policy_test.rego` + pytest wrapper). ✅
- Add `--config` CLI flag → Task 1. ✅
- Add Rev 5 OSCAL baseline fetch to sync → Task 8. ✅
- Full parity across providers → Task 7 parity test. ✅

**Type/contract consistency:** Normalized payload keys are identical in every collector and asserted in Task 7 (`PAYLOAD_KEYS`). `rego_package` (`fr20x.iam_mfa`) matches the policy `package` line and `mapping.yaml`. NIST IDs use OSCAL lowercase dotted form, matching `engine/render/oscal.py`. `_run_slice` keeps its Plan-1 call shape plus an optional `config`. `sync()` is untouched, so Task 12's tests stay green.

**Known limitations carried forward (documented, not bugs):** per-user privilege granularity (IA-2(1) vs (2)) is collapsed into "all human users"; principal IDs are stored unhashed; policy-enforcement booleans for Okta/Google are supplied via `config` because those APIs don't expose a single flag; baseline-sync URLs must be verified against the live GSA repo on first online run.
