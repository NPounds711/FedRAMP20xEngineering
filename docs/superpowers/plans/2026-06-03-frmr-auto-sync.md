# FRMR Auto-Sync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep the repo's FedRAMP reference data current automatically — a daily GitHub Actions job pulls the consolidated FRMR, detects drift against the committed snapshot, cross-references it against the slices we ship, auto-drafts safe id-renames, and opens a reviewer-assigned PR (with email notification) for anything that needs a human.

**Architecture:** A pure, unit-tested Python module `tools/frmr_drift.py` does all the parsing/diffing/cross-referencing/drafting (no network in the tested paths — the live doc is injected). A thin CLI (`python -m tools.frmr_drift`) wires it to a freshly-fetched FRMR and the filesystem. A GitHub Actions workflow runs the CLI on a cron and turns its output into a PR + email. The existing `tools/sync.py` gains one fetch helper for the consolidated file and is otherwise untouched.

**Tech Stack:** Python 3.12, pytest, PyYAML (already a dep), `urllib` (stdlib, already used by `sync.py`), GitHub Actions (`peter-evans/create-pull-request`, `dawidd6/action-send-mail`).

**Working rules (do not violate):** Commit locally only — never push or merge (the repo owner does that). Never add an AI-attribution trailer or any reference to the drafting tool in commits or content. Commit with `git -c commit.gpgsign=false commit`. Run python via `.venv/bin/python` (system python is 3.8.5).

---

## FRMR structure (locked — tasks below depend on this exact shape)

The source file is `FRMR.documentation.json` from `https://raw.githubusercontent.com/FedRAMP/docs/main/FRMR.documentation.json`. Its KSI section:
```json
{ "KSI": { "IAM": { "id": "KSI-IAM", "indicators": {
  "KSI-IAM-MFA": {
    "fka": "KSI-IAM-01",
    "statement": "Enforce multi-factor authentication ...",
    "controls": ["ia-2", "ia-2.1"],
    "updated": [{"date": "...", "comment": "..."}]
  }
}}}}
```
- The mnemonic id is the **key** under `indicators`. `fka` ("formerly known as") is the old numbered id, present only when renamed. `controls` is the NIST 800-53 mapping (lowercase). No `"FRMR"` wrapper; families and indicators are **dicts**, not lists. (This is why the old `extract_obligations`/`diff_catalog` are NOT reused — they parse the old per-file list shape.)

## File structure

- `tools/sync.py` — add `DOC_FILE` const + `sync_documentation(dest, offline_dir=None)` (mirrors `sync()`'s contract). Existing functions untouched.
- `tools/frmr_drift.py` (new) — `extract_ksis`, `diff_ksis`, `load_slice_ksis`, `affected`, `draft_mapping_edits`, `summarize`, `run`, `main`.
- `tests/fixtures/frmr/doc_old.json`, `tests/fixtures/frmr/doc_new.json` (new) — minimal consolidated-shape fixtures exercising rename/remove/restate/control-change/no-change.
- `tests/test_frmr_drift.py` (new) — unit tests for every function.
- `catalog/FRMR.documentation.json` (new committed snapshot) — the live file, seeded once; the diff baseline.
- `.github/workflows/frmr-sync.yml` (new) — the scheduled workflow.
- `docs/onboarding/auto-sync.md` (new) — one-time setup + how it works.

---

### Task 0: Consolidated-FRMR fetch helper

**Files:**
- Modify: `tools/sync.py`
- Test: `tests/test_sync_documentation.py`

- [ ] **Step 1: Write the failing test** — `tests/test_sync_documentation.py`:

```python
from tools.sync import DOC_FILE, sync_documentation


def test_sync_documentation_offline(tmp_path):
    offline = tmp_path / "src"
    offline.mkdir()
    (offline / DOC_FILE).write_text('{"KSI": {}}')
    dest = tmp_path / "catalog"

    result = sync_documentation(str(dest), offline_dir=str(offline))

    assert DOC_FILE in result["written"]
    assert (dest / DOC_FILE).exists()
    assert result["failed"] == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_sync_documentation.py -v`
Expected: FAIL — `ImportError: cannot import name 'DOC_FILE'`.

- [ ] **Step 3: Add the helper to `tools/sync.py`** (after the `_fetch` definition; reuse `FRMR_BASE`, `_fetch`, and the same `(urllib.error.URLError, OSError)` handling as `sync()`):

```python
# The consolidated machine-readable FRMR (definitions, requirements, KSIs) — the
# single source of truth for auto-sync. Uses the current mnemonic KSI ids and
# carries `fka` (old numbered ids) + per-KSI `controls`.
DOC_FILE = "FRMR.documentation.json"


def sync_documentation(dest, offline_dir=None) -> dict:
    """Sync the consolidated FRMR.documentation.json into dest.

    Same contract as sync(): {"written": {name: bytes}, "failed": {name: err}}.
    Online fetch failure is recorded under "failed" (never silently ignored); in
    offline mode an absent file is skipped.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    written, failed = {}, {}
    try:
        if offline_dir is not None:
            source = Path(offline_dir) / DOC_FILE
            if source.exists():
                content = source.read_text()
            else:
                return {"written": {}, "failed": {}}
        else:
            content = _fetch(FRMR_BASE + DOC_FILE)
    except (urllib.error.URLError, OSError) as exc:
        return {"written": {}, "failed": {DOC_FILE: str(exc)}}
    (dest / DOC_FILE).write_text(content)
    written[DOC_FILE] = len(content)
    return {"written": written, "failed": failed}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_sync_documentation.py tests/test_sync.py -v`
Expected: PASS (existing `test_sync.py` still green — `sync()` unchanged).

- [ ] **Step 5: Seed the catalog snapshot**

Fetch the live file once so the diff has a baseline. Run:
```bash
.venv/bin/python -c "from tools.sync import sync_documentation; print(sync_documentation('catalog'))"
```
Expected: prints `{'written': {'FRMR.documentation.json': <bytes>}, 'failed': {}}` and creates `catalog/FRMR.documentation.json`. Verify it parses and has KSIs:
```bash
.venv/bin/python -c "import json; d=json.load(open('catalog/FRMR.documentation.json')); print('families:', list(d['KSI'])); assert 'KSI-IAM-MFA' in d['KSI']['IAM']['indicators']"
```

- [ ] **Step 6: Commit**

```bash
git add tools/sync.py tests/test_sync_documentation.py catalog/FRMR.documentation.json
git -c commit.gpgsign=false commit -m "Add consolidated FRMR fetch helper and seed catalog snapshot"
```

---

### Task 1: `extract_ksis` + fixtures

**Files:**
- Create: `tools/frmr_drift.py`
- Create: `tests/fixtures/frmr/doc_old.json`, `tests/fixtures/frmr/doc_new.json`
- Test: `tests/test_frmr_drift.py`

- [ ] **Step 1: Create the two fixtures.**

`tests/fixtures/frmr/doc_old.json`:
```json
{
  "info": {"version": "old"},
  "KSI": {
    "IAM": {"id": "KSI-IAM", "indicators": {
      "KSI-IAM-01": {"statement": "Enforce phishing-resistant MFA.", "controls": ["ia-2", "ia-2.1"]},
      "KSI-IAM-OLD": {"statement": "Soon to be removed.", "controls": ["ia-5"]}
    }},
    "CNA": {"id": "KSI-CNA", "indicators": {
      "KSI-CNA-RNT": {"statement": "Limit inbound and outbound traffic.", "controls": ["sc-7"]}
    }}
  }
}
```

`tests/fixtures/frmr/doc_new.json`:
```json
{
  "info": {"version": "new"},
  "KSI": {
    "IAM": {"id": "KSI-IAM", "indicators": {
      "KSI-IAM-MFA": {"fka": "KSI-IAM-01", "statement": "Enforce phishing-resistant MFA.", "controls": ["ia-2", "ia-2.1"]},
      "KSI-IAM-NEW": {"statement": "A brand new indicator.", "controls": ["ia-8"]}
    }},
    "CNA": {"id": "KSI-CNA", "indicators": {
      "KSI-CNA-RNT": {"statement": "Limit inbound and outbound network traffic everywhere.", "controls": ["sc-7", "sc-7.5"]}
    }}
  }
}
```
(This models: `KSI-IAM-01`→`KSI-IAM-MFA` rename via `fka`; `KSI-IAM-OLD` removed; `KSI-IAM-NEW` added; `KSI-CNA-RNT` restated **and** controls changed.)

- [ ] **Step 2: Write the failing test** — start `tests/test_frmr_drift.py`:

```python
import json
from pathlib import Path

from tools import frmr_drift

FIX = Path(__file__).resolve().parent / "fixtures" / "frmr"
OLD = json.loads((FIX / "doc_old.json").read_text())
NEW = json.loads((FIX / "doc_new.json").read_text())


def test_extract_ksis_flattens_indicators():
    out = frmr_drift.extract_ksis(NEW)
    assert set(out) == {"KSI-IAM-MFA", "KSI-IAM-NEW", "KSI-CNA-RNT"}
    mfa = out["KSI-IAM-MFA"]
    assert mfa["family"] == "IAM"
    assert mfa["fka"] == "KSI-IAM-01"
    assert mfa["controls"] == ["ia-2", "ia-2.1"]
    assert "phishing-resistant" in mfa["statement"]
    # absent fka -> None; controls always a sorted list
    assert out["KSI-IAM-NEW"]["fka"] is None
    assert frmr_drift.extract_ksis({})["KSI-IAM-MFA"] if False else True  # empty doc is safe
    assert frmr_drift.extract_ksis({}) == {}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_frmr_drift.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'tools.frmr_drift'`.

- [ ] **Step 4: Create `tools/frmr_drift.py` with `extract_ksis`**

```python
import json
from pathlib import Path

import yaml


def extract_ksis(frmr_doc) -> dict:
    """Flatten the KSI section of a consolidated FRMR doc.

    Returns {ksi_id: {"family", "statement", "fka": str|None, "controls": sorted[str]}}.
    """
    out = {}
    for family, fam_obj in (frmr_doc.get("KSI", {}) or {}).items():
        for ksi_id, ind in (fam_obj.get("indicators", {}) or {}).items():
            out[ksi_id] = {
                "family": family,
                "statement": str(ind.get("statement", "")).strip(),
                "fka": ind.get("fka"),
                "controls": sorted(ind.get("controls", []) or []),
            }
    return out
```

- [ ] **Step 5: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_frmr_drift.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add tools/frmr_drift.py tests/fixtures/frmr tests/test_frmr_drift.py
git -c commit.gpgsign=false commit -m "Add frmr_drift.extract_ksis and FRMR diff fixtures"
```

---

### Task 2: `diff_ksis`

**Files:**
- Modify: `tools/frmr_drift.py`
- Test: `tests/test_frmr_drift.py`

- [ ] **Step 1: Write the failing test** (append to `tests/test_frmr_drift.py`):

```python
def test_diff_ksis_categorizes_every_change():
    d = frmr_drift.diff_ksis(frmr_drift.extract_ksis(OLD), frmr_drift.extract_ksis(NEW))
    assert d["renamed"] == [{"old": "KSI-IAM-01", "new": "KSI-IAM-MFA"}]
    assert d["added"] == ["KSI-IAM-NEW"]            # the rename target is NOT "added"
    assert d["removed"] == ["KSI-IAM-OLD"]          # the rename source is NOT "removed"
    assert d["restated"] == ["KSI-CNA-RNT"]
    assert d["controls_changed"] == ["KSI-CNA-RNT"]


def test_diff_ksis_no_change_is_empty():
    same = frmr_drift.extract_ksis(NEW)
    d = frmr_drift.diff_ksis(same, same)
    assert all(d[k] == [] for k in d)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_frmr_drift.py::test_diff_ksis_categorizes_every_change -v`
Expected: FAIL — `AttributeError: module 'tools.frmr_drift' has no attribute 'diff_ksis'`.

- [ ] **Step 3: Add `diff_ksis` to `tools/frmr_drift.py`**

```python
def diff_ksis(old, new) -> dict:
    """Structured diff between two extract_ksis() results.

    A rename is a NEW indicator whose `fka` names an id that was in OLD and is no
    longer a current id in NEW. Rename source/target are excluded from removed/added.
    """
    old_ids, new_ids = set(old), set(new)
    renamed, renamed_old, renamed_new = [], set(), set()
    for nid, n in new.items():
        fka = n.get("fka")
        if fka and fka in old_ids and fka not in new_ids:
            renamed.append({"old": fka, "new": nid})
            renamed_old.add(fka)
            renamed_new.add(nid)
    common = old_ids & new_ids
    return {
        "added": sorted(new_ids - old_ids - renamed_new),
        "removed": sorted(old_ids - new_ids - renamed_old),
        "renamed": sorted(renamed, key=lambda r: r["old"]),
        "restated": sorted(i for i in common if old[i]["statement"] != new[i]["statement"]),
        "controls_changed": sorted(i for i in common if old[i]["controls"] != new[i]["controls"]),
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_frmr_drift.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tools/frmr_drift.py tests/test_frmr_drift.py
git -c commit.gpgsign=false commit -m "Add frmr_drift.diff_ksis change categorization"
```

---

### Task 3: `load_slice_ksis` + `affected`

**Files:**
- Modify: `tools/frmr_drift.py`
- Test: `tests/test_frmr_drift.py`

- [ ] **Step 1: Write the failing test** (append):

```python
def test_load_slice_ksis_reads_real_mappings():
    root = Path(__file__).resolve().parent.parent
    m = frmr_drift.load_slice_ksis(root / "slices")
    # the shipped slices map to these mnemonic ids
    assert "network-restriction" in m.get("KSI-CNA-RNT", [])
    assert "iam-mfa" in m.get("KSI-IAM-MFA", [])


def test_affected_classifies_by_change(tmp_path):
    # a tiny slice tree mapping to the ids our fixtures change
    for name, ksi in [("slice-a", "KSI-IAM-01"), ("slice-b", "KSI-CNA-RNT"), ("slice-c", "KSI-IAM-OLD")]:
        d = tmp_path / name
        d.mkdir()
        (d / "mapping.yaml").write_text(f"capability: {name}\nksis:\n  - id: {ksi}\n    obligation: required\n")
    diff = frmr_drift.diff_ksis(frmr_drift.extract_ksis(OLD), frmr_drift.extract_ksis(NEW))
    items = frmr_drift.affected(diff, frmr_drift.load_slice_ksis(tmp_path))
    by_slice = {i["slice"]: i for i in items}
    assert by_slice["slice-a"]["change"] == "renamed" and by_slice["slice-a"]["auto_fixable"] is True
    assert by_slice["slice-a"]["detail"] == "KSI-IAM-MFA"
    assert by_slice["slice-c"]["change"] == "removed" and by_slice["slice-c"]["auto_fixable"] is False
    # slice-b is hit by BOTH restated and controls_changed (two records), neither auto-fixable
    assert all(i["auto_fixable"] is False for i in items if i["slice"] == "slice-b")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_frmr_drift.py::test_affected_classifies_by_change -v`
Expected: FAIL — `AttributeError: ... has no attribute 'load_slice_ksis'`.

- [ ] **Step 3: Add both functions to `tools/frmr_drift.py`**

```python
def load_slice_ksis(slices_dir) -> dict:
    """Map each KSI id referenced by a slice's mapping.yaml to the slice name(s)."""
    out = {}
    for mapping in sorted(Path(slices_dir).glob("*/mapping.yaml")):
        data = yaml.safe_load(mapping.read_text()) or {}
        for k in data.get("ksis", []):
            out.setdefault(k["id"], []).append(mapping.parent.name)
    return out


def affected(diff, slice_ksis) -> list:
    """One record per (change, slice) where a change touches a KSI a slice maps to.

    Only `renamed` is auto_fixable; removals/restatements/control changes need a human.
    """
    items = []
    for r in diff["renamed"]:
        for s in slice_ksis.get(r["old"], []):
            items.append({"slice": s, "ksi": r["old"], "change": "renamed",
                          "detail": r["new"], "auto_fixable": True})
    for change in ("removed", "restated", "controls_changed"):
        for ksi in diff[change]:
            for s in slice_ksis.get(ksi, []):
                items.append({"slice": s, "ksi": ksi, "change": change,
                              "detail": "", "auto_fixable": False})
    return items
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_frmr_drift.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tools/frmr_drift.py tests/test_frmr_drift.py
git -c commit.gpgsign=false commit -m "Add slice cross-reference and change classification to frmr_drift"
```

---

### Task 4: `draft_mapping_edits` + `summarize`

**Files:**
- Modify: `tools/frmr_drift.py`
- Test: `tests/test_frmr_drift.py`

- [ ] **Step 1: Write the failing test** (append):

```python
def test_draft_mapping_edits_applies_rename_only(tmp_path):
    a = tmp_path / "slice-a"; a.mkdir()
    (a / "mapping.yaml").write_text("capability: slice-a\nksis:\n  - id: KSI-IAM-01\n    obligation: required\n")
    c = tmp_path / "slice-c"; c.mkdir()
    (c / "mapping.yaml").write_text("capability: slice-c\nksis:\n  - id: KSI-IAM-OLD\n    obligation: required\n")
    diff = frmr_drift.diff_ksis(frmr_drift.extract_ksis(OLD), frmr_drift.extract_ksis(NEW))
    aff = frmr_drift.affected(diff, frmr_drift.load_slice_ksis(tmp_path))

    edits = frmr_drift.draft_mapping_edits(aff, tmp_path, apply=True)

    assert edits == [{"path": str(a / "mapping.yaml"), "old": "KSI-IAM-01", "new": "KSI-IAM-MFA"}]
    assert "KSI-IAM-MFA" in (a / "mapping.yaml").read_text()   # rename applied
    assert "KSI-IAM-OLD" in (c / "mapping.yaml").read_text()   # removal NOT auto-edited


def test_summarize_separates_auto_and_manual():
    diff = frmr_drift.diff_ksis(frmr_drift.extract_ksis(OLD), frmr_drift.extract_ksis(NEW))
    aff = [
        {"slice": "iam-mfa", "ksi": "KSI-IAM-01", "change": "renamed", "detail": "KSI-IAM-MFA", "auto_fixable": True},
        {"slice": "iam-mfa", "ksi": "KSI-IAM-OLD", "change": "removed", "detail": "", "auto_fixable": False},
    ]
    body = frmr_drift.summarize(diff, aff)
    assert "Auto-drafted" in body and "KSI-IAM-01` → `KSI-IAM-MFA" in body
    assert "Needs your decision" in body and "removed" in body
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_frmr_drift.py::test_draft_mapping_edits_applies_rename_only -v`
Expected: FAIL — `AttributeError: ... has no attribute 'draft_mapping_edits'`.

- [ ] **Step 3: Add both functions to `tools/frmr_drift.py`**

```python
def draft_mapping_edits(affected_items, slices_dir, apply=False) -> list:
    """For renames only, substitute old->new KSI id in the slice's mapping.yaml.
    Returns the edits; applies them in place when apply=True. Non-renames are ignored."""
    edits = []
    for item in affected_items:
        if item["change"] != "renamed" or not item["auto_fixable"]:
            continue
        path = Path(slices_dir) / item["slice"] / "mapping.yaml"
        edits.append({"path": str(path), "old": item["ksi"], "new": item["detail"]})
        if apply:
            path.write_text(path.read_text().replace(item["ksi"], item["detail"]))
    return edits


def summarize(diff, affected_items) -> str:
    """Human-readable PR body: change counts + auto-drafted vs needs-decision lists."""
    lines = [
        "## FRMR auto-sync",
        "",
        (f"Changes: {len(diff['added'])} added, {len(diff['removed'])} removed, "
         f"{len(diff['renamed'])} renamed, {len(diff['restated'])} restated, "
         f"{len(diff['controls_changed'])} control-set changes."),
        "",
    ]
    auto = [a for a in affected_items if a["auto_fixable"]]
    manual = [a for a in affected_items if not a["auto_fixable"]]
    if auto:
        lines += ["### Auto-drafted in this PR (id renames)"]
        lines += [f"- `{a['slice']}`: `{a['ksi']}` → `{a['detail']}`" for a in auto] + [""]
    if manual:
        lines += ["### ⚠️ Needs your decision (not auto-applied)"]
        lines += [f"- `{a['slice']}`: `{a['ksi']}` was **{a['change']}**" for a in manual] + [""]
    if not affected_items:
        lines += ["No shipped slice is affected; this PR only refreshes the catalog."]
    return "\n".join(lines)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_frmr_drift.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tools/frmr_drift.py tests/test_frmr_drift.py
git -c commit.gpgsign=false commit -m "Add rename auto-drafting and PR-body summary to frmr_drift"
```

---

### Task 5: orchestration `run` + CLI `main`

**Files:**
- Modify: `tools/frmr_drift.py`
- Test: `tests/test_frmr_drift.py`

- [ ] **Step 1: Write the failing test** (append):

```python
def test_run_reports_changed_and_summary(tmp_path):
    catalog = tmp_path / "catalog" / "FRMR.documentation.json"
    catalog.parent.mkdir(parents=True)
    catalog.write_text(json.dumps(OLD))
    slices = tmp_path / "slices"; (slices / "iam-mfa").mkdir(parents=True)
    (slices / "iam-mfa" / "mapping.yaml").write_text("capability: iam-mfa\nksis:\n  - id: KSI-IAM-01\n    obligation: required\n")

    result = frmr_drift.run(str(catalog), str(slices), NEW)

    assert result["changed"] is True
    assert any(a["change"] == "renamed" for a in result["affected"])
    assert "FRMR auto-sync" in result["summary"]


def test_run_no_change(tmp_path):
    catalog = tmp_path / "FRMR.documentation.json"
    catalog.write_text(json.dumps(NEW))
    slices = tmp_path / "slices"; slices.mkdir()
    result = frmr_drift.run(str(catalog), str(slices), NEW)
    assert result["changed"] is False


def test_main_apply_writes_catalog_and_summary(tmp_path, monkeypatch):
    catalog = tmp_path / "catalog" / "FRMR.documentation.json"
    catalog.parent.mkdir(parents=True)
    catalog.write_text(json.dumps(OLD))
    slices = tmp_path / "slices"; (slices / "iam-mfa").mkdir(parents=True)
    (slices / "iam-mfa" / "mapping.yaml").write_text("capability: iam-mfa\nksis:\n  - id: KSI-IAM-01\n    obligation: required\n")
    new_path = tmp_path / "new.json"; new_path.write_text(json.dumps(NEW))
    summary = tmp_path / "summary.md"
    gh_out = tmp_path / "gh_out"

    rc = frmr_drift.main([
        "--catalog", str(catalog), "--slices", str(slices),
        "--offline-doc", str(new_path), "--summary-out", str(summary),
        "--github-output", str(gh_out), "--apply",
    ])

    assert rc == 0
    assert json.loads(catalog.read_text())["info"]["version"] == "new"     # catalog refreshed
    assert "KSI-IAM-MFA" in (slices / "iam-mfa" / "mapping.yaml").read_text()  # rename applied
    assert "FRMR auto-sync" in summary.read_text()
    assert "changed=true" in gh_out.read_text()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_frmr_drift.py::test_run_reports_changed_and_summary -v`
Expected: FAIL — `AttributeError: ... has no attribute 'run'`.

- [ ] **Step 3: Add `run` and `main` to `tools/frmr_drift.py`**

```python
def run(catalog_path, slices_dir, new_doc) -> dict:
    """Diff a fetched FRMR doc against the committed catalog snapshot. Pure: writes nothing."""
    catalog_path = Path(catalog_path)
    old_doc = json.loads(catalog_path.read_text()) if catalog_path.exists() else {"KSI": {}}
    diff = diff_ksis(extract_ksis(old_doc), extract_ksis(new_doc))
    changed = any(diff[k] for k in diff)
    aff = affected(diff, load_slice_ksis(slices_dir))
    return {"changed": changed, "diff": diff, "affected": aff, "summary": summarize(diff, aff)}


def _load_doc(offline_doc):
    if offline_doc:
        return json.loads(Path(offline_doc).read_text())
    from tools.sync import DOC_FILE, FRMR_BASE, _fetch
    return json.loads(_fetch(FRMR_BASE + DOC_FILE))


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="frmr-drift")
    p.add_argument("--catalog", default="catalog/FRMR.documentation.json")
    p.add_argument("--slices", default="slices")
    p.add_argument("--offline-doc", help="read the new FRMR from a local file instead of the network")
    p.add_argument("--summary-out", help="write the PR-body summary to this path")
    p.add_argument("--github-output", help="append changed=<bool> for GitHub Actions")
    p.add_argument("--apply", action="store_true", help="write the refreshed catalog and apply rename edits")
    args = p.parse_args(argv)

    new_doc = _load_doc(args.offline_doc)
    result = run(args.catalog, args.slices, new_doc)

    if args.apply and result["changed"]:
        Path(args.catalog).write_text(json.dumps(new_doc, indent=2, sort_keys=True))
        draft_mapping_edits(result["affected"], args.slices, apply=True)
    if args.summary_out:
        Path(args.summary_out).write_text(result["summary"])
    if args.github_output:
        with open(args.github_output, "a") as fh:
            fh.write(f"changed={'true' if result['changed'] else 'false'}\n")
    print(result["summary"])
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_frmr_drift.py -v`
Expected: PASS (all frmr_drift tests). Then full suite `.venv/bin/python -m pytest -q` — no regressions.

- [ ] **Step 5: Commit**

```bash
git add tools/frmr_drift.py tests/test_frmr_drift.py
git -c commit.gpgsign=false commit -m "Add frmr_drift run/main orchestration and CLI"
```

---

### Task 6: GitHub Actions workflow + onboarding doc

**Files:**
- Create: `.github/workflows/frmr-sync.yml`
- Create: `docs/onboarding/auto-sync.md`
- Test: `tests/test_workflow_present.py`

- [ ] **Step 1: Write the failing test** — `tests/test_workflow_present.py`:

```python
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
WF = ROOT / ".github" / "workflows" / "frmr-sync.yml"


def test_workflow_is_valid_and_wired():
    assert WF.exists()
    wf = yaml.safe_load(WF.read_text())
    # 'on' parses as True in YAML 1.1; accept either key
    triggers = wf.get("on", wf.get(True))
    assert "schedule" in triggers and "workflow_dispatch" in triggers
    text = WF.read_text()
    # runs the drift CLI with --apply, opens a PR, requests review, sends email
    assert "tools.frmr_drift" in text and "--apply" in text
    assert "create-pull-request" in text
    assert "reviewers" in text and "frmr-sync" in text
    assert "action-send-mail" in text


def test_onboarding_doc_present():
    doc = (ROOT / "docs" / "onboarding" / "auto-sync.md").read_text()
    assert "Allow GitHub Actions to create and approve pull requests" in doc
    assert "secret" in doc.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_workflow_present.py -v`
Expected: FAIL — workflow file missing.

- [ ] **Step 3: Create `.github/workflows/frmr-sync.yml`**

```yaml
name: FRMR auto-sync

on:
  schedule:
    - cron: "17 7 * * *"   # daily ~07:17 UTC
  workflow_dispatch: {}

permissions:
  contents: write
  pull-requests: write

jobs:
  sync:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install PyYAML

      - name: Detect FRMR drift and draft fixes
        id: drift
        run: |
          python -m tools.frmr_drift \
            --catalog catalog/FRMR.documentation.json \
            --slices slices \
            --summary-out frmr-summary.md \
            --github-output "$GITHUB_OUTPUT" \
            --apply

      - name: Open or update review PR
        if: steps.drift.outputs.changed == 'true'
        uses: peter-evans/create-pull-request@v6
        id: cpr
        with:
          branch: frmr-sync
          commit-message: "Sync FRMR catalog and draft slice fixes"
          title: "FRMR auto-sync: review FedRAMP updates"
          body-path: frmr-summary.md
          labels: frmr-sync
          reviewers: NPounds711
          assignees: NPounds711

      - name: Email on PR open
        if: steps.drift.outputs.changed == 'true'
        uses: dawidd6/action-send-mail@v3
        with:
          server_address: ${{ secrets.SMTP_HOST }}
          server_port: ${{ secrets.SMTP_PORT }}
          username: ${{ secrets.SMTP_USER }}
          password: ${{ secrets.SMTP_PASS }}
          from: FRMR Auto-Sync <${{ secrets.SMTP_USER }}>
          to: ${{ secrets.NOTIFY_EMAIL }}
          subject: "FRMR auto-sync PR opened for review"
          body: |
            FedRAMP FRMR changed. A review PR is open:
            ${{ steps.cpr.outputs.pull-request-url }}

      - name: Fail loudly if the FRMR source could not be fetched
        if: failure()
        uses: dawidd6/action-send-mail@v3
        with:
          server_address: ${{ secrets.SMTP_HOST }}
          server_port: ${{ secrets.SMTP_PORT }}
          username: ${{ secrets.SMTP_USER }}
          password: ${{ secrets.SMTP_PASS }}
          from: FRMR Auto-Sync <${{ secrets.SMTP_USER }}>
          to: ${{ secrets.NOTIFY_EMAIL }}
          subject: "FRMR auto-sync FAILED (source may have moved)"
          body: "The FRMR sync job failed — the source URL may have changed. Check the Actions run."
```

- [ ] **Step 4: Create `docs/onboarding/auto-sync.md`**

```markdown
# FRMR auto-sync

A scheduled GitHub Actions workflow (`.github/workflows/frmr-sync.yml`) keeps the
FedRAMP reference data current. Daily it pulls `FRMR.documentation.json`, diffs it
against `catalog/FRMR.documentation.json`, and — if anything changed — refreshes the
catalog, auto-drafts safe KSI id-renames into the affected `slices/*/mapping.yaml`,
and opens a PR assigned to you. Removals, statement changes, and control-set changes
are flagged in the PR body for your decision (never auto-applied).

## One-time setup
1. **Repo setting:** Settings → Actions → General → Workflow permissions → enable
   **"Allow GitHub Actions to create and approve pull requests"**.
2. **Email secrets** (Settings → Secrets and variables → Actions): add `SMTP_HOST`,
   `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, and `NOTIFY_EMAIL`. (Any SMTP provider; or
   swap the email step for your provider's API.)
3. **Notifications:** keep GitHub email/mobile notifications on so the "review
   requested" ping reaches you even between emails.

## Trigger it manually
Actions → "FRMR auto-sync" → "Run workflow" (uses `workflow_dispatch`) to prove the
end-to-end path before relying on the daily cron.

## Local dry-run
`.venv/bin/python -m tools.frmr_drift --summary-out /tmp/s.md` prints the change
summary against the live FRMR without writing anything (omit `--apply`).
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_workflow_present.py -v`
Expected: PASS. Then full suite `.venv/bin/python -m pytest -q` — all pass.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/frmr-sync.yml docs/onboarding/auto-sync.md tests/test_workflow_present.py
git -c commit.gpgsign=false commit -m "Add FRMR auto-sync workflow and onboarding doc"
```

---

## Self-Review

**Spec coverage:**
- Source = consolidated FRMR → Task 0 (`sync_documentation` + seeded `catalog/`). ✅
- Refresh + auto-draft renames → PR for review → Tasks 4–6. ✅
- Drift for KSI id/statement/**control** changes → Task 2 (`diff_ksis` incl. `controls_changed`). ✅
- Cross-reference against shipped slices + classify → Task 3. ✅
- Renames-only auto-draft; removals/rewrites flagged → Tasks 3–4 (`auto_fixable`) + summary. ✅
- GitHub Actions, daily, PR + native(reviewer/assignee/label) + email → Task 6. ✅
- URL-moved guard fails loudly + emails → Task 0 (`failed` reporting) + Task 6 (`if: failure()` email). ✅
- One-time setup documented → Task 6 onboarding doc. ✅

**Placeholder scan:** none — every code/test step is complete; `NPounds711` and the SMTP secret names are concrete.

**Type consistency:** `extract_ksis` record shape (`family/statement/fka/controls`) is consumed identically by `diff_ksis`/`run`; `affected` records (`slice/ksi/change/detail/auto_fixable`) are consumed identically by `draft_mapping_edits`/`summarize`/`main`. `run` returns `{changed,diff,affected,summary}` and `main` reads `result["affected"]`/`["changed"]`/`["summary"]` — consistent. The drift CLI flags in Task 5 (`--catalog/--slices/--offline-doc/--summary-out/--github-output/--apply`) match exactly what the workflow invokes in Task 6.

**Known limitation (documented):** `draft_mapping_edits` uses a literal id string-replace in `mapping.yaml` — safe because KSI ids are unique tokens; if a future mapping embeds an id as a substring of another token this would need a YAML-aware edit. Out of scope for v1.
