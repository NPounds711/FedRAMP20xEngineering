# FRMR Auto-Sync — Design

**Status:** Approved 2026-06-03, pre-implementation.

**Goal:** Keep the repo's FedRAMP reference data current automatically. When FedRAMP publishes an update to its machine-readable rules, a scheduled GitHub Actions job refreshes the committed catalog, detects whether any change affects a slice we ship, drafts the safe fixes, and **opens a pull request for human review** — notifying the maintainer natively on GitHub and by email. Slice "claims" (the KSI ids a slice maps to) are never changed silently.

## Background / why

FedRAMP 20x is changing quickly and across multiple parallel tracks, which we confirmed by inspection on 2026-06-03:
- `FedRAMP/docs-alpha` holds the per-file FRMR for the **25.12A Phase 2 Pilot** release, using **numbered** KSI ids (`KSI-IAM-01`, `KSI-CNA-01`).
- `FedRAMP/2026` holds the newest ruleset using **mnemonic** ids (`KSI-IAM-MFA`, `KSI-CNA-RNT`), but it is **site/markdown content with no machine-readable feed**.
- `FedRAMP/docs/FRMR.documentation.json` is a **consolidated machine-readable FRMR** (v0.9.43-beta, last updated 2026-04-08) that carries the **mnemonic 2026 ids** *and* the numbered ids side by side (an effective old→new crosswalk).

The repo's existing `tools/sync.py` points at a now-stale path (`FedRAMP/docs/main/FRMR.KSI.key-security-indicators.json`, which 404s). Manual tracking is error-prone — we nearly published outdated KSI ids. This feature makes "always have the latest" automatic and safe.

## Decisions (locked)

| Decision | Value |
|---|---|
| Source of truth | `FedRAMP/docs/FRMR.documentation.json` (consolidated FRMR; mnemonic ids + numbered crosswalk). Replaces the stale per-file URL in `tools/sync.py`. |
| Reaction model | Refresh data + **auto-draft** safe mapping fixes → **PR for review**. Never auto-merge slice claim changes. |
| Mechanism | GitHub Actions scheduled workflow (`workflow_dispatch` + cron) that opens/updates a PR. Runs server-side; no dependency on a local machine. |
| Cadence | Daily (revisitable; FedRAMP changes are infrequent, daily keeps lag < 24h with near-zero cost). |
| Notification | Native GitHub (request reviewer + assign + label `frmr-sync`) **plus an email** on PR open. |
| Auto-draft aggressiveness | Only unambiguous **id renames** (resolved via the file's own numbered↔mnemonic crosswalk) are auto-edited. **Removals, merges, and statement rewrites are flagged for a human decision, never auto-applied.** |

## Components

- **`catalog/FRMR.documentation.json` (committed snapshot)** — the "last-known" state the job diffs against. Updated by the sync PR.
- **`tools/sync.py` (repoint + reuse)** — change the FRMR source to `https://raw.githubusercontent.com/FedRAMP/docs/main/FRMR.documentation.json`; reuse the existing `_fetch` + resilient written/failed reporting. (Confirm the exact raw URL/branch at implementation time; the GitHub default branch for `FedRAMP/docs` is `main`.)
- **`tools/frmr_drift.py` (new, pure, unit-tested)** — the core logic:
  - `extract_ksis(frmr_doc) -> {id: {statement, crosswalk_ids, controls?}}` — normalize the KSI section of the FRMR into a comparable structure.
  - `diff(old, new) -> {added, removed, renamed, restated}` — structured change set between two FRMR snapshots.
  - `affected_slices(change_set, slice_dir) -> [{slice, mapped_ksi, change, severity}]` — cross-reference every `slices/*/mapping.yaml` KSI id against the change set; classify each change as **slice-affecting** or **informational**.
  - `draft_mapping_edits(affected) -> [edits]` — for **renames only**, produce the exact `mapping.yaml` id substitution. Removals/merges/restatements produce a **flag**, not an edit.
- **`.github/workflows/frmr-sync.yml`** — orchestration: checkout → run sync + drift → if changed, commit refreshed catalog + drafted edits to a `frmr-sync` branch → open/update PR (title, body, reviewer, assignee, label) → send email. Uses a maintained create-PR action (e.g. `peter-evans/create-pull-request`) and an email action/API step.

## Data flow (daily run)

```
cron (daily) / manual workflow_dispatch
  → fetch live FRMR.documentation.json
  → diff vs committed catalog/FRMR.documentation.json
        └─ no normalized change ──► exit: no PR, no email, no noise
  → categorize: informational (catalog refresh) vs slice-affecting
  → refresh catalog snapshot
  → auto-draft mapping.yaml edits for safe id-renames only
  → open/update PR  "FRMR sync <version> (<date>): N changes, M affect slices"
        body: human-readable summary + ⚠️ items needing a human decision
        + request maintainer as reviewer, assign, label `frmr-sync`
  → send email (PR link + summary)
→ maintainer reviews → approve/merge, or resolve the flagged items by hand
```

## Safety & error handling

- **No silent claim changes.** Only mechanical id-renames are auto-drafted. Removal / merge / statement change is surfaced in the PR body as a ⚠️ "human decision required" item.
- **URL-moved guard.** If the fetch 404s or returns non-JSON (the exact failure mode we hit on 2026-06-03), the job **fails loudly and emails** — silence must never be mistaken for "no updates."
- **No duplicate or noisy PRs.** Reuse a single `frmr-sync` branch; only open/update a PR when the *normalized* extracted content changed (ignore whitespace and key ordering).
- **Deterministic diff.** Compare the normalized KSI set (ids + statements, + control mappings if present), not raw bytes.
- **Idempotent.** Re-running with no upstream change is a no-op.

## Testing

- `tools/frmr_drift.py` unit-tested with fixture **old/new** FRMR JSON pairs covering: no-change, id-rename, KSI removal, new KSI, reworded statement. All offline (no network).
- `affected_slices` tested against the real `slices/*/mapping.yaml` files (e.g. a fixture renaming `KSI-CNA-RNT` must flag the `network-restriction` slice and draft the edit).
- `draft_mapping_edits` tested to confirm it edits on rename and **refuses** to edit on removal/restatement.
- Workflow YAML validated; first execution via `workflow_dispatch` proves the end-to-end path (PR + reviewer + label + email) before relying on the cron.

## One-time setup (documented for the maintainer, not code)

- Enable **"Allow GitHub Actions to create and approve pull requests"** in repo settings (needed for the workflow to open PRs).
- Add an **email-sending secret** (SMTP creds, or a Resend/SendGrid API key) as a repo secret; the workflow reads it to send the notification.
- Ensure GitHub notifications (email and/or the mobile app) are on for the repo so the native "review requested" pings land.

## Open item to confirm during planning

Whether `FRMR.documentation.json` carries an explicit **KSI → NIST 800-53 control-id** mapping. If it does, `frmr_drift` also diffs control drift and can flag a slice whose mapped control changed; if not, v1 diffs KSI ids/statements only and the NIST control ids in each slice's `mapping.yaml` remain maintainer-owned.

## Scope (YAGNI)

- **In v1:** repoint sync to the consolidated FRMR; drift detection for KSI id/statement changes; cross-reference + classify against shipped slices; auto-draft safe id-renames; daily workflow that opens a reviewed PR with native + email notification.
- **Out of v1:** auto-generating slices for brand-new KSIs; tracking multiple releases simultaneously; Rev5 change diffing; Slack/other channels; auto-merge of any kind.
