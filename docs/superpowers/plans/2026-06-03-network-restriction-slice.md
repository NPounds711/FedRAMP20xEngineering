# Network Restriction Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `network-restriction` evidence slice — proving cloud network boundaries are **deny-by-default with allow-by-exception**, with **no admin ports (SSH/RDP) reachable directly from the internet** — collected with parity across AWS, Azure, and GCP, evaluated by one shared Rego policy, and aligned to KSI-CNA-RNT + NIST AC-17(3) and SC-7(5).

**Architecture:** A new slice `slices/network-restriction/` following the established slice contract (see `slices/iam-mfa/` as the worked reference): one `mapping.yaml`, one **shared** provider-agnostic `policy/policy.rego` + `policy_test.rego`, one collector per provider under `collectors/` (each a pure unit-tested `normalize(raw)` plus a `collect(config)` that lazily imports its cloud SDK and supports a `{"raw": {...}}` offline seam), a Terraform compliant/non-compliant pair, and a README. Every collector maps its provider's ingress rules into one uniform `raw` shape, so the `normalize()` body — and therefore the normalized payload the Rego sees — is identical across providers. No engine changes are needed (Plan 2 already added `--config` and baseline sync).

**Tech Stack:** Python 3.12, pytest, PyYAML, jsonschema, Open Policy Agent (`opa` binary, `opa test`). Collector SDKs (`boto3`, `azure-mgmt-network`+`azure-identity`, `google-cloud-compute`) are **optional extras**, lazily imported inside `collect()` only.

**Working rules (do not violate):** Commit locally only — never push or merge (the repo owner does that). Never add an AI-attribution trailer or any reference to the drafting tool in commits or content. Commit with `git -c commit.gpgsign=false commit`.

---

## Contracts this plan depends on (already in `main` — must match exactly)

- `engine/collect.py`: `collect(slice_dir, provider, config=None)` loads `collectors/<provider>.py` via importlib as a **standalone file** and calls its `collect(config)`. A collector **cannot import sibling files** — keep each self-contained.
- `engine/evaluate.py`: Rego must expose `result := {"pass": bool, "violations": [...]}`; engine reads `value.get("pass")` and `value.get("violations", [])`.
- `engine/align.py`: reads `mapping["capability"]`, `mapping["title"]`, `mapping.get("ksis", [])` (`{id, obligation}`), `mapping.get("nist_controls", [])`.
- `engine/render/oscal.py`: NIST control ids render verbatim as OSCAL `control-id` → use **lowercase dotted OSCAL form**: `ac-17.3`, `sc-7.5`.
- `engine/cli.py`: `fr20x run-slice <slice> --provider <p> --run-id <id> --evidence-dir <d> --config <json>` (the `--config` JSON, when it contains `"raw"`, drives the offline collector seam).

## The normalized payload contract (the heart of this slice)

**Every** collector's `collect(config)` returns this exact shape; the shared Rego evaluates only this:

```json
{
  "scope": "ingress-rules",
  "default_deny": true,
  "rules_evaluated": 6,
  "public_admin_exposures": [{"id": "sg-a/tcp/0", "port": "22", "cidr": "0.0.0.0/0"}],
  "unrestricted_ingress": [{"id": "sg-a/tcp/4", "port": "8000-9000", "cidr": "0.0.0.0/0"}]
}
```

- `default_deny` — the boundary's baseline posture denies inbound (SC-7(5)). Each collector derives this per-platform (documented in its docstring); `normalize()` passes it through.
- `public_admin_exposures` — internet-open (`0.0.0.0/0` / `::/0`) rules whose port range covers an admin port (22 SSH, 3389 RDP). Direct internet admin access bypasses managed access control points (AC-17(3)).
- `unrestricted_ingress` — internet-open rules spanning a **wide** port range (all-traffic, or span ≥ 100 ports). These are blanket-allow, the opposite of allow-by-exception (SC-7(5)).
- A **narrow, non-admin** internet-open rule (e.g. tcp/443 to `0.0.0.0/0`) is treated as an intentional public-service exception and is **not** flagged — flagging it would over-report legitimate public endpoints.

Classification is shared, pure logic (`_is_open`, `_covers_admin`, `_is_wide`, `_port_label`) duplicated verbatim in each collector — justified because the engine loads collectors as standalone files (no sibling imports), exactly as in the iam-mfa slice.

---

### Task 0: Slice scaffold, mapping, azure extra, README skeleton

**Files:**
- Create: `slices/network-restriction/mapping.yaml`
- Create: `slices/network-restriction/README.md`
- Modify: `pyproject.toml` (add `azure` extra + extend `collectors`)
- Test: `tests/test_netrestrict_mapping.py`

- [ ] **Step 1: Write the failing test** — `tests/test_netrestrict_mapping.py`:

```python
from pathlib import Path

from engine.slice import load_mapping

SLICE = Path(__file__).resolve().parent.parent / "slices" / "network-restriction"


def test_mapping_validates_and_targets_the_right_controls():
    m = load_mapping(SLICE)
    assert m["capability"] == "network-restriction"
    assert m["rego_package"] == "fr20x.network_restriction"
    assert {k["id"] for k in m["ksis"]} == {"KSI-CNA-RNT"}
    assert m["ksis"][0]["obligation"] == "required"
    assert set(m["nist_controls"]) == {"ac-17.3", "sc-7.5"}
    assert set(m["providers"]) == {"aws", "azure", "gcp"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_netrestrict_mapping.py -v`
Expected: FAIL — `FileNotFoundError` on the missing `mapping.yaml`.

- [ ] **Step 3: Create the mapping and README**

`slices/network-restriction/mapping.yaml`:
```yaml
capability: network-restriction
title: Default-Deny Network Boundaries with Managed Remote Access
ksis:
  - id: KSI-CNA-RNT
    obligation: required
nist_controls:
  - ac-17.3
  - sc-7.5
providers:
  - aws
  - azure
  - gcp
evidence_source: "Cloud network control plane (AWS security groups, Azure NSGs, GCP VPC firewall rules)"
rego_package: fr20x.network_restriction
```

`slices/network-restriction/README.md`:
```markdown
# Slice: network-restriction

## What this slice proves
Cloud network boundaries are **deny-by-default, allow-by-exception**, and **no admin
port (SSH 22 / RDP 3389) is reachable directly from the internet** — satisfying 20x
**KSI-CNA-RNT** and NIST **AC-17(3)** (managed access points) and **SC-7(5)**
(deny by default) with one collected fact per provider.

## Normalized payload (identical across every provider)
| Field | Meaning |
|---|---|
| `default_deny` | Boundary baseline denies inbound (SC-7(5)) |
| `public_admin_exposures` | Internet-open rules reaching SSH/RDP (AC-17(3)) |
| `unrestricted_ingress` | Internet-open rules spanning a wide port range (SC-7(5)) |
| `rules_evaluated` | Count of ingress rules considered |

A narrow non-admin public rule (e.g. tcp/443 to `0.0.0.0/0`) is treated as an
intentional exception and is not flagged.

## Run it
```bash
fr20x run-slice slices/network-restriction --provider aws \
  --run-id 2026-06-03-aws --config my-aws.json > det.json
fr20x render det.json --format oscal
fr20x verify network-restriction
```
For an offline dry-run, pass `--config` a file of `{"raw": { ...normalized-shaped raw... }}`.

## Policy tests
`opa test slices/network-restriction/policy`
```

- [ ] **Step 4: Add the `azure` extra to `pyproject.toml`**

In `[project.optional-dependencies]`, add an `azure` group and extend `collectors`. The block becomes:
```toml
[project.optional-dependencies]
dev = ["pytest>=8.0"]
okta = ["requests>=2.31"]
entra = ["msgraph-sdk>=1.0"]
azure = ["azure-mgmt-network>=25.0", "azure-identity>=1.15"]
aws = ["boto3>=1.34"]
gcp = ["google-api-python-client>=2.0", "google-auth>=2.0", "google-cloud-compute>=1.14"]
collectors = [
  "requests>=2.31",
  "msgraph-sdk>=1.0",
  "azure-mgmt-network>=25.0",
  "azure-identity>=1.15",
  "boto3>=1.34",
  "google-api-python-client>=2.0",
  "google-auth>=2.0",
  "google-cloud-compute>=1.14",
]
```

- [ ] **Step 5: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_netrestrict_mapping.py -v`
Expected: PASS. Then full suite `.venv/bin/python -m pytest -q` — no regressions (baseline 58 → 59 passed).

- [ ] **Step 6: Commit**

```bash
git add slices/network-restriction/mapping.yaml slices/network-restriction/README.md pyproject.toml tests/test_netrestrict_mapping.py
git -c commit.gpgsign=false commit -m "Scaffold network-restriction slice mapping, README, and azure extra"
```

---

### Task 1: Shared Rego policy + `opa test`

**Files:**
- Create: `slices/network-restriction/policy/policy.rego`
- Create: `slices/network-restriction/policy/policy_test.rego`
- Test: `tests/test_netrestrict_policy.py`

- [ ] **Step 1: Write the policy and its Rego unit tests**

`slices/network-restriction/policy/policy.rego`:
```rego
# Provider-agnostic network-restriction policy. Evaluates the normalized payload
# emitted identically by every collector. Package MUST match mapping.yaml `rego_package`.
package fr20x.network_restriction

import rego.v1

violations contains msg if {
	input.default_deny != true
	msg := "default-deny network posture is not enforced (SC-7(5))"
}

violations contains msg if {
	count(input.public_admin_exposures) > 0
	ids := [e.id | some e in input.public_admin_exposures]
	msg := sprintf("%d rule(s) expose an admin port to the internet, bypassing managed access points (AC-17(3)): %v", [count(input.public_admin_exposures), ids])
}

violations contains msg if {
	count(input.unrestricted_ingress) > 0
	ids := [e.id | some e in input.unrestricted_ingress]
	msg := sprintf("%d rule(s) allow unrestricted internet ingress instead of allow-by-exception (SC-7(5)): %v", [count(input.unrestricted_ingress), ids])
}

# REQUIRED decision document consumed by the engine. Do not rename.
result := {"pass": count(violations) == 0, "violations": violations}
```

`slices/network-restriction/policy/policy_test.rego`:
```rego
package fr20x.network_restriction_test

import rego.v1

import data.fr20x.network_restriction

compliant := {
	"scope": "ingress-rules",
	"default_deny": true,
	"rules_evaluated": 3,
	"public_admin_exposures": [],
	"unrestricted_ingress": [],
}

noncompliant := {
	"scope": "ingress-rules",
	"default_deny": false,
	"rules_evaluated": 3,
	"public_admin_exposures": [{"id": "sg-a/tcp/0", "port": "22", "cidr": "0.0.0.0/0"}],
	"unrestricted_ingress": [{"id": "sg-a/tcp/4", "port": "8000-9000", "cidr": "0.0.0.0/0"}],
}

test_compliant_passes if {
	network_restriction.result.pass with input as compliant
}

test_noncompliant_fails if {
	not network_restriction.result.pass with input as noncompliant
}

test_all_three_violations_fire if {
	count(network_restriction.result.violations) == 3 with input as noncompliant
}
```

- [ ] **Step 2: Run the Rego tests**

Run: `opa test slices/network-restriction/policy -v`
Expected: `PASS: 3/3`. If OPA 1.16.2 rejects any syntax, adjust to preserve identical behavior and report the change.

- [ ] **Step 3: Write the pytest wrapper** — `tests/test_netrestrict_policy.py`:

```python
import subprocess
from pathlib import Path

import pytest

from engine.evaluate import opa_available

POLICY_DIR = Path(__file__).resolve().parent.parent / "slices" / "network-restriction" / "policy"


@pytest.mark.skipif(not opa_available(), reason="opa binary not installed")
def test_opa_unit_tests_pass():
    proc = subprocess.run(
        ["opa", "test", str(POLICY_DIR)],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
```

- [ ] **Step 4: Run it**

Run: `.venv/bin/python -m pytest tests/test_netrestrict_policy.py -v`
Expected: PASS. Then full suite `.venv/bin/python -m pytest -q` — no regressions (60 passed).

- [ ] **Step 5: Commit**

```bash
git add slices/network-restriction/policy tests/test_netrestrict_policy.py
git -c commit.gpgsign=false commit -m "Add shared network-restriction Rego policy with opa unit tests"
```

---

### Task 2: AWS collector

**Files:**
- Create: `slices/network-restriction/collectors/aws.py`
- Test: `tests/test_netrestrict_aws.py`

The collector splits a pure `normalize(raw)` + shared classification helpers (tested here) from `collect(config)` (lazy `boto3`, with a `{"raw": {...}}` offline seam). The `raw` shape is uniform across all three providers:
`{"default_deny": bool, "rules": [{"id": str, "protocol": str, "from_port": int|None, "to_port": int|None, "cidr": str}, ...]}`.

- [ ] **Step 1: Write the failing test** — `tests/test_netrestrict_aws.py`:

```python
import importlib.util
from pathlib import Path

COLLECTOR = Path(__file__).resolve().parent.parent / "slices" / "network-restriction" / "collectors" / "aws.py"


def _load():
    spec = importlib.util.spec_from_file_location("netr_aws", COLLECTOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_normalize_classifies_ingress_rules():
    aws = _load()
    raw = {
        "default_deny": True,
        "rules": [
            {"id": "sg-a/tcp/0", "protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"},      # admin
            {"id": "sg-a/tcp/1", "protocol": "tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0"},    # exception, not flagged
            {"id": "sg-a/tcp/2", "protocol": "tcp", "from_port": 5432, "to_port": 5432, "cidr": "10.0.0.0/8"}, # internal, ignored
            {"id": "sg-a/all/3", "protocol": "-1", "from_port": None, "to_port": None, "cidr": "0.0.0.0/0"},   # all-traffic -> admin
            {"id": "sg-a/tcp/4", "protocol": "tcp", "from_port": 8000, "to_port": 9000, "cidr": "0.0.0.0/0"},  # wide -> unrestricted
            {"id": "sg-a/tcp/5", "protocol": "tcp", "from_port": 3389, "to_port": 3389, "cidr": "::/0"},       # admin (rdp, ipv6)
        ],
    }
    out = aws.normalize(raw)
    assert out["scope"] == "ingress-rules"
    assert out["default_deny"] is True
    assert out["rules_evaluated"] == 6
    assert [e["id"] for e in out["public_admin_exposures"]] == ["sg-a/all/3", "sg-a/tcp/0", "sg-a/tcp/5"]
    assert [e["id"] for e in out["unrestricted_ingress"]] == ["sg-a/tcp/4"]
    assert out["public_admin_exposures"][1]["port"] == "22"
    assert out["public_admin_exposures"][0]["port"] == "all"


def test_collect_uses_offline_raw_seam():
    aws = _load()
    out = aws.collect({"raw": {
        "default_deny": True,
        "rules": [{"id": "sg-x/tcp/0", "protocol": "tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0"}],
    }})
    assert out["public_admin_exposures"] == []
    assert out["unrestricted_ingress"] == []
    assert out["rules_evaluated"] == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_netrestrict_aws.py -v`
Expected: FAIL — collector file does not exist.

- [ ] **Step 3: Write the collector** — `slices/network-restriction/collectors/aws.py`:

```python
# AWS collector for the network-restriction slice.
#
# `normalize(raw)` + the classification helpers are pure and unit-tested. `collect(config)`
# queries EC2 security groups (lazy `boto3`) and maps them into the uniform `raw` shape,
# then normalizes. Pass {"raw": {...}} for an offline dry-run.
#
# config (live mode): {"region": "us-gov-west-1"}
# default_deny is derived as: the VPC default security group has no ingress rules
# (AWS security groups are implicitly deny-by-default; an empty default SG is the
# best-practice signal). config may override with {"default_deny": bool}.

_ADMIN_PORTS = (22, 3389)
_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def _is_open(rule):
    return rule.get("cidr") in _OPEN_CIDRS


def _covers_admin(rule):
    lo, hi = rule.get("from_port"), rule.get("to_port")
    if lo is None or hi is None:          # all-traffic rule
        return True
    return any(lo <= p <= hi for p in _ADMIN_PORTS)


def _is_wide(rule, threshold=100):
    lo, hi = rule.get("from_port"), rule.get("to_port")
    if lo is None or hi is None:          # all-traffic rule
        return True
    return (hi - lo) >= threshold


def _port_label(rule):
    lo, hi = rule.get("from_port"), rule.get("to_port")
    if lo is None or hi is None:
        return "all"
    return str(lo) if lo == hi else f"{lo}-{hi}"


def normalize(raw):
    rules = raw.get("rules", [])
    admin, unrestricted = [], []
    for r in rules:
        if not _is_open(r):
            continue
        entry = {"id": r["id"], "port": _port_label(r), "cidr": r["cidr"]}
        if _covers_admin(r):
            admin.append(entry)
        elif _is_wide(r):
            unrestricted.append(entry)
        # else: narrow non-admin public rule = intentional exception, not flagged
    return {
        "scope": "ingress-rules",
        "default_deny": bool(raw.get("default_deny", False)),
        "rules_evaluated": len(rules),
        "public_admin_exposures": sorted(admin, key=lambda e: e["id"]),
        "unrestricted_ingress": sorted(unrestricted, key=lambda e: e["id"]),
    }


def collect(config):
    if "raw" in config:
        return normalize(config["raw"])
    import boto3  # optional dep: pip install '.[aws]'

    ec2 = boto3.client("ec2", region_name=config.get("region"))
    groups = ec2.describe_security_groups()["SecurityGroups"]

    rules = []
    default_has_ingress = False
    for sg in groups:
        for i, perm in enumerate(sg.get("IpPermissions", [])):
            proto = str(perm.get("IpProtocol", "-1"))
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            cidrs = [r["CidrIp"] for r in perm.get("IpRanges", [])]
            cidrs += [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])]
            for j, cidr in enumerate(cidrs):
                rules.append({
                    "id": f"{sg['GroupId']}/{proto}/{i}-{j}",
                    "protocol": proto,
                    "from_port": from_port,
                    "to_port": to_port,
                    "cidr": cidr,
                })
            if sg.get("GroupName") == "default" and perm.get("IpPermissions") is not None:
                default_has_ingress = True
        if sg.get("GroupName") == "default" and sg.get("IpPermissions"):
            default_has_ingress = True

    default_deny = config.get("default_deny", not default_has_ingress)
    return normalize({"default_deny": default_deny, "rules": rules})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_netrestrict_aws.py -v`
Expected: PASS (no SDK needed — `boto3` is lazy and tests hit only `normalize`/the raw seam). Then full suite `.venv/bin/python -m pytest -q` (62 passed).

- [ ] **Step 5: Commit**

```bash
git add slices/network-restriction/collectors/aws.py tests/test_netrestrict_aws.py
git -c commit.gpgsign=false commit -m "Add AWS collector for the network-restriction slice"
```

---

### Task 3: Azure collector

**Files:**
- Create: `slices/network-restriction/collectors/azure.py`
- Test: `tests/test_netrestrict_azure.py`

Same pure `normalize` + helpers as AWS (duplicated — standalone-file loader). `collect(config)` lazily imports `azure-mgmt-network` + `azure-identity`, lists NSG inbound Allow rules, maps them into the uniform `raw` shape.

- [ ] **Step 1: Write the failing test** — `tests/test_netrestrict_azure.py`:

```python
import importlib.util
from pathlib import Path

COLLECTOR = Path(__file__).resolve().parent.parent / "slices" / "network-restriction" / "collectors" / "azure.py"


def _load():
    spec = importlib.util.spec_from_file_location("netr_azure", COLLECTOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_normalize_classifies_ingress_rules():
    azure = _load()
    raw = {
        "default_deny": True,
        "rules": [
            {"id": "nsg-web/AllowRDP", "protocol": "Tcp", "from_port": 3389, "to_port": 3389, "cidr": "0.0.0.0/0"},  # admin
            {"id": "nsg-web/AllowHTTPS", "protocol": "Tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0"},  # exception
            {"id": "nsg-web/AllowAll", "protocol": "*", "from_port": 0, "to_port": 65535, "cidr": "0.0.0.0/0"},      # wide -> unrestricted
            {"id": "nsg-web/Internal", "protocol": "Tcp", "from_port": 1433, "to_port": 1433, "cidr": "10.0.0.0/8"}, # ignored
        ],
    }
    out = azure.normalize(raw)
    assert out["rules_evaluated"] == 4
    assert [e["id"] for e in out["public_admin_exposures"]] == ["nsg-web/AllowRDP"]
    assert [e["id"] for e in out["unrestricted_ingress"]] == ["nsg-web/AllowAll"]


def test_collect_uses_offline_raw_seam():
    azure = _load()
    out = azure.collect({"raw": {
        "default_deny": True,
        "rules": [{"id": "nsg/AllowHTTPS", "protocol": "Tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0"}],
    }})
    assert out["public_admin_exposures"] == []
    assert out["unrestricted_ingress"] == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_netrestrict_azure.py -v`
Expected: FAIL — collector file does not exist.

- [ ] **Step 3: Write the collector** — `slices/network-restriction/collectors/azure.py`:

```python
# Azure collector for the network-restriction slice.
#
# `normalize(raw)` + helpers are pure and unit-tested. `collect(config)` lists NSG
# inbound Allow rules (lazy azure-mgmt-network + azure-identity) and maps them into
# the uniform `raw` shape. Pass {"raw": {...}} for an offline dry-run.
#
# config (live mode): {"subscription_id": "..."}
# Azure NSGs default-deny inbound (default rule DenyAllInBound, priority 65500), so
# default_deny defaults True; config may override with {"default_deny": bool}.
# Source prefixes "*", "Internet", and "0.0.0.0/0" are normalized to "0.0.0.0/0".

_ADMIN_PORTS = (22, 3389)
_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
_OPEN_SOURCES = {"*", "internet", "0.0.0.0/0", "::/0"}


def _is_open(rule):
    return rule.get("cidr") in _OPEN_CIDRS


def _covers_admin(rule):
    lo, hi = rule.get("from_port"), rule.get("to_port")
    if lo is None or hi is None:
        return True
    return any(lo <= p <= hi for p in _ADMIN_PORTS)


def _is_wide(rule, threshold=100):
    lo, hi = rule.get("from_port"), rule.get("to_port")
    if lo is None or hi is None:
        return True
    return (hi - lo) >= threshold


def _port_label(rule):
    lo, hi = rule.get("from_port"), rule.get("to_port")
    if lo is None or hi is None:
        return "all"
    return str(lo) if lo == hi else f"{lo}-{hi}"


def normalize(raw):
    rules = raw.get("rules", [])
    admin, unrestricted = [], []
    for r in rules:
        if not _is_open(r):
            continue
        entry = {"id": r["id"], "port": _port_label(r), "cidr": r["cidr"]}
        if _covers_admin(r):
            admin.append(entry)
        elif _is_wide(r):
            unrestricted.append(entry)
    return {
        "scope": "ingress-rules",
        "default_deny": bool(raw.get("default_deny", False)),
        "rules_evaluated": len(rules),
        "public_admin_exposures": sorted(admin, key=lambda e: e["id"]),
        "unrestricted_ingress": sorted(unrestricted, key=lambda e: e["id"]),
    }


def _port_bounds(port_range):
    # Azure destination_port_range is "*", "80", or "8000-9000".
    if port_range in ("*", None):
        return None, None
    if "-" in port_range:
        lo, hi = port_range.split("-", 1)
        return int(lo), int(hi)
    return int(port_range), int(port_range)


def collect(config):
    if "raw" in config:
        return normalize(config["raw"])
    import os

    from azure.identity import DefaultAzureCredential  # optional dep: pip install '.[azure]'
    from azure.mgmt.network import NetworkManagementClient

    sub = config.get("subscription_id") or os.environ["AZURE_SUBSCRIPTION_ID"]
    client = NetworkManagementClient(DefaultAzureCredential(), sub)

    rules = []
    for nsg in client.network_security_groups.list_all():
        for rule in (nsg.security_rules or []):
            if rule.direction != "Inbound" or rule.access != "Allow":
                continue
            source = (rule.source_address_prefix or "").lower()
            if source not in _OPEN_SOURCES:
                continue
            lo, hi = _port_bounds(rule.destination_port_range)
            rules.append({
                "id": f"{nsg.name}/{rule.name}",
                "protocol": rule.protocol,
                "from_port": lo,
                "to_port": hi,
                "cidr": "0.0.0.0/0",
            })

    default_deny = config.get("default_deny", True)
    return normalize({"default_deny": default_deny, "rules": rules})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_netrestrict_azure.py -v`
Expected: PASS. Then full suite `.venv/bin/python -m pytest -q` (64 passed).

- [ ] **Step 5: Commit**

```bash
git add slices/network-restriction/collectors/azure.py tests/test_netrestrict_azure.py
git -c commit.gpgsign=false commit -m "Add Azure collector for the network-restriction slice"
```

---

### Task 4: GCP collector

**Files:**
- Create: `slices/network-restriction/collectors/gcp.py`
- Test: `tests/test_netrestrict_gcp.py`

Same pure `normalize` + helpers. `collect(config)` lazily imports `google-cloud-compute`, lists INGRESS allow firewall rules with `0.0.0.0/0` source ranges, maps to the uniform `raw` shape.

- [ ] **Step 1: Write the failing test** — `tests/test_netrestrict_gcp.py`:

```python
import importlib.util
from pathlib import Path

COLLECTOR = Path(__file__).resolve().parent.parent / "slices" / "network-restriction" / "collectors" / "gcp.py"


def _load():
    spec = importlib.util.spec_from_file_location("netr_gcp", COLLECTOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_normalize_classifies_ingress_rules():
    gcp = _load()
    raw = {
        "default_deny": True,
        "rules": [
            {"id": "default-allow-ssh", "protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"},   # admin
            {"id": "allow-https", "protocol": "tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0"},       # exception
            {"id": "allow-all", "protocol": "all", "from_port": None, "to_port": None, "cidr": "0.0.0.0/0"},       # all -> admin
        ],
    }
    out = gcp.normalize(raw)
    assert out["rules_evaluated"] == 3
    assert [e["id"] for e in out["public_admin_exposures"]] == ["allow-all", "default-allow-ssh"]
    assert out["unrestricted_ingress"] == []


def test_collect_uses_offline_raw_seam():
    gcp = _load()
    out = gcp.collect({"raw": {
        "default_deny": True,
        "rules": [{"id": "allow-https", "protocol": "tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0"}],
    }})
    assert out["public_admin_exposures"] == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_netrestrict_gcp.py -v`
Expected: FAIL — collector file does not exist.

- [ ] **Step 3: Write the collector** — `slices/network-restriction/collectors/gcp.py`:

```python
# GCP collector for the network-restriction slice.
#
# `normalize(raw)` + helpers are pure and unit-tested. `collect(config)` lists VPC
# firewall rules (lazy google-cloud-compute) and maps INGRESS allow rules open to
# 0.0.0.0/0 into the uniform `raw` shape. Pass {"raw": {...}} for an offline dry-run.
#
# config (live mode): {"project": "my-project"}
# GCP VPC networks have an implied deny-all ingress, so default_deny defaults True;
# config may override with {"default_deny": bool}. A firewall "allowed" entry with
# no ports (e.g. protocol "all" or "icmp") maps to from/to_port = None (all-traffic).

_ADMIN_PORTS = (22, 3389)
_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def _is_open(rule):
    return rule.get("cidr") in _OPEN_CIDRS


def _covers_admin(rule):
    lo, hi = rule.get("from_port"), rule.get("to_port")
    if lo is None or hi is None:
        return True
    return any(lo <= p <= hi for p in _ADMIN_PORTS)


def _is_wide(rule, threshold=100):
    lo, hi = rule.get("from_port"), rule.get("to_port")
    if lo is None or hi is None:
        return True
    return (hi - lo) >= threshold


def _port_label(rule):
    lo, hi = rule.get("from_port"), rule.get("to_port")
    if lo is None or hi is None:
        return "all"
    return str(lo) if lo == hi else f"{lo}-{hi}"


def normalize(raw):
    rules = raw.get("rules", [])
    admin, unrestricted = [], []
    for r in rules:
        if not _is_open(r):
            continue
        entry = {"id": r["id"], "port": _port_label(r), "cidr": r["cidr"]}
        if _covers_admin(r):
            admin.append(entry)
        elif _is_wide(r):
            unrestricted.append(entry)
    return {
        "scope": "ingress-rules",
        "default_deny": bool(raw.get("default_deny", False)),
        "rules_evaluated": len(rules),
        "public_admin_exposures": sorted(admin, key=lambda e: e["id"]),
        "unrestricted_ingress": sorted(unrestricted, key=lambda e: e["id"]),
    }


def collect(config):
    if "raw" in config:
        return normalize(config["raw"])
    from google.cloud import compute_v1  # optional dep: pip install '.[gcp]'

    project = config["project"]
    client = compute_v1.FirewallsClient()

    rules = []
    for fw in client.list(project=project):
        if fw.direction != "INGRESS" or not fw.allowed:
            continue
        if "0.0.0.0/0" not in list(fw.source_ranges):
            continue
        for allowed in fw.allowed:
            ports = list(allowed.ports) if allowed.ports else []
            if not ports:
                lo = hi = None
            else:
                first = ports[0]
                if "-" in first:
                    a, b = first.split("-", 1)
                    lo, hi = int(a), int(b)
                else:
                    lo = hi = int(first)
            rules.append({
                "id": fw.name,
                "protocol": allowed.I_p_protocol,
                "from_port": lo,
                "to_port": hi,
                "cidr": "0.0.0.0/0",
            })

    default_deny = config.get("default_deny", True)
    return normalize({"default_deny": default_deny, "rules": rules})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_netrestrict_gcp.py -v`
Expected: PASS. Then full suite `.venv/bin/python -m pytest -q` (66 passed).

- [ ] **Step 5: Commit**

```bash
git add slices/network-restriction/collectors/gcp.py tests/test_netrestrict_gcp.py
git -c commit.gpgsign=false commit -m "Add GCP collector for the network-restriction slice"
```

---

### Task 5: Cross-provider parity + end-to-end through the engine

**Files:**
- Test: `tests/test_netrestrict_e2e.py`

- [ ] **Step 1: Write the test** — `tests/test_netrestrict_e2e.py`:

```python
import importlib.util
import json
from pathlib import Path

import pytest

from engine.cli import main
from engine.evaluate import opa_available

ROOT = Path(__file__).resolve().parent.parent
SLICE = ROOT / "slices" / "network-restriction"
PROVIDERS = ["aws", "azure", "gcp"]
PAYLOAD_KEYS = {
    "scope", "default_deny", "rules_evaluated",
    "public_admin_exposures", "unrestricted_ingress",
}

COMPLIANT_RAW = {
    "default_deny": True,
    "rules": [{"id": "sg/tcp/0", "protocol": "tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0"}],
}
NONCOMPLIANT_RAW = {
    "default_deny": False,
    "rules": [{"id": "sg/tcp/0", "protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"}],
}


def _load(provider):
    path = SLICE / "collectors" / f"{provider}.py"
    spec = importlib.util.spec_from_file_location(f"netr_{provider}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("provider", PROVIDERS)
def test_all_providers_emit_the_same_shape(provider):
    out = _load(provider).collect({"raw": COMPLIANT_RAW})
    assert set(out.keys()) == PAYLOAD_KEYS


@pytest.mark.skipif(not opa_available(), reason="opa binary not installed")
def test_pipeline_pass_via_config(tmp_path, capsys):
    cfg = tmp_path / "aws.json"
    cfg.write_text(json.dumps({"raw": COMPLIANT_RAW}))
    rc = main([
        "run-slice", str(SLICE), "--provider", "aws", "--run-id", "netr-ok",
        "--evidence-dir", str(tmp_path / "ev"), "--config", str(cfg),
    ])
    assert rc == 0
    det = json.loads(capsys.readouterr().out)
    assert det["capability"] == "network-restriction"
    assert det["result"] == "pass"
    assert det["frameworks"]["nist-800-53-rev5"] == ["ac-17.3", "sc-7.5"]
    assert det["frameworks"]["fedramp-20x"][0]["ksi"] == "KSI-CNA-RNT"
    assert main(["verify", "network-restriction", "--evidence-dir", str(tmp_path / "ev")]) == 0


@pytest.mark.skipif(not opa_available(), reason="opa binary not installed")
def test_pipeline_fail_via_config(tmp_path, capsys):
    cfg = tmp_path / "aws.json"
    cfg.write_text(json.dumps({"raw": NONCOMPLIANT_RAW}))
    rc = main([
        "run-slice", str(SLICE), "--provider", "aws", "--run-id", "netr-bad",
        "--evidence-dir", str(tmp_path / "ev"), "--config", str(cfg),
    ])
    assert rc == 0
    det = json.loads(capsys.readouterr().out)
    assert det["result"] == "fail"
    # default_deny false + an SSH-open rule => at least the deny-default and admin violations
    assert len(det["violations"]) >= 2
```

- [ ] **Step 2: Run the tests**

Run: `.venv/bin/python -m pytest tests/test_netrestrict_e2e.py -v`
Expected: 3 parity cases PASS + both end-to-end cases PASS (opa present). Then full suite `.venv/bin/python -m pytest -q` (69 passed).

- [ ] **Step 3: Commit**

```bash
git add tests/test_netrestrict_e2e.py
git -c commit.gpgsign=false commit -m "Add cross-provider parity and end-to-end tests for network-restriction"
```

---

### Task 6: Terraform reference pair + finalize docs

**Files:**
- Create: `slices/network-restriction/terraform/compliant.tf`
- Create: `slices/network-restriction/terraform/noncompliant.tf`
- Modify: `slices/network-restriction/README.md` (append Terraform + per-provider config)
- Test: `tests/test_netrestrict_files.py`

- [ ] **Step 1: Write the failing test** — `tests/test_netrestrict_files.py`:

```python
from pathlib import Path

SLICE = Path(__file__).resolve().parent.parent / "slices" / "network-restriction"


def test_slice_has_all_required_files():
    required = [
        "mapping.yaml", "README.md",
        "policy/policy.rego", "policy/policy_test.rego",
        "collectors/aws.py", "collectors/azure.py", "collectors/gcp.py",
        "terraform/compliant.tf", "terraform/noncompliant.tf",
    ]
    for rel in required:
        assert (SLICE / rel).exists(), rel
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_netrestrict_files.py -v`
Expected: FAIL — terraform files missing.

- [ ] **Step 3: Write the Terraform pair**

`slices/network-restriction/terraform/compliant.tf`:
```hcl
# COMPLIANT reference: a security group that allows only HTTPS from the internet and
# restricts SSH to an internal management CIDR — admin access never reaches 0.0.0.0/0,
# and there is no wide-open ingress. The collector reports empty exposure lists.
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

resource "aws_security_group" "web" {
  name        = "web-restricted"
  description = "HTTPS public, SSH internal only"

  ingress {
    description = "HTTPS from anywhere (intentional public service)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH from the management network only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

`slices/network-restriction/terraform/noncompliant.tf`:
```hcl
# NON-COMPLIANT variant: SSH open to the entire internet (admin port exposure) — the
# collector reports it under public_admin_exposures and the Rego fails. Apply only in
# a throwaway account to demonstrate the policy catches the gap.
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

resource "aws_security_group" "web_insecure" {
  name        = "web-insecure"
  description = "SSH exposed to the internet"

  ingress {
    description = "SSH from anywhere (violation: AC-17(3))"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

- [ ] **Step 4: Append the Terraform + config section to the slice README**

Append to `slices/network-restriction/README.md`:
```markdown

## Terraform reference
- `terraform/compliant.tf` — HTTPS public, SSH restricted to an internal CIDR.
- `terraform/noncompliant.tf` — SSH open to `0.0.0.0/0` (admin exposure; policy fails).
Apply the non-compliant variant in a throwaway account to prove the Rego catches it.
Per-provider Terraform for Azure/GCP is a documented follow-on.

## Per-provider `--config`
| Provider | Required config keys |
|---|---|
| `aws` | `region` (optional `default_deny` override) |
| `azure` | `subscription_id` (optional `default_deny` override) |
| `gcp` | `project` (optional `default_deny` override) |
Every provider also accepts `{"raw": {...}}` for an offline dry-run (no network).
```

- [ ] **Step 5: Run the file-presence test**

Run: `.venv/bin/python -m pytest tests/test_netrestrict_files.py -v`
Expected: PASS.

- [ ] **Step 6: Run the full suite**

Run: `.venv/bin/python -m pytest -q`
Expected: all pass (70 passed). opa-dependent tests run (opa is installed).

- [ ] **Step 7: Commit**

```bash
git add slices/network-restriction/terraform slices/network-restriction/README.md tests/test_netrestrict_files.py
git -c commit.gpgsign=false commit -m "Add network-restriction Terraform reference pair and finalize slice docs"
```

---

## Self-Review

**Spec coverage (against the locked design for the network-restriction starter slice):**
- KSI-CNA-RNT / AC-17(3) + SC-7(5) → Task 0 mapping (`ac-17.3`, `sc-7.5`). ✅
- Shared provider-agnostic Rego → Task 1 (deny-by-default, admin-exposure, unrestricted-ingress). ✅
- Real collectors AWS / Azure / GCP → Tasks 2–4 (security groups / NSGs / VPC firewall rules). ✅
- `opa test` → Task 1. ✅
- Compliant / non-compliant Terraform → Task 6. ✅
- Full parity across providers + end-to-end → Task 5. ✅

**Type/contract consistency:** Normalized payload keys (`scope`, `default_deny`, `rules_evaluated`, `public_admin_exposures`, `unrestricted_ingress`) are identical in every collector and asserted in Task 5 (`PAYLOAD_KEYS`). `rego_package` (`fr20x.network_restriction`) matches the policy `package` and `mapping.yaml`. NIST ids use OSCAL lowercase dotted form, matching `engine/render/oscal.py`. The classification helpers (`_is_open`, `_covers_admin`, `_is_wide`, `_port_label`) are byte-identical across the three collectors (deliberate duplication; standalone-file loader prevents sharing).

**No engine changes:** Plan 2 already delivered `--config` and baseline sync, so this slice is pure slice content — lower risk than Plan 2.

**Known limitations carried forward (documented, not bugs):** `default_deny` is a per-platform heuristic derived in `collect()` (AWS: empty default SG; Azure/GCP: platform implied-deny baseline) and overridable via config — it is not a deep audit of every route table / NACL / hierarchical firewall policy; egress is out of scope (ingress-focused for v1); the `_is_wide` threshold (≥100 ports) is a deliberate, documented heuristic for "blanket allow" vs "narrow exception"; live `collect()` SDK paths are untested by design (covered by `normalize` + the raw seam); KSI/control ids should be verified against the synced FRMR catalog before formal reporting.
