# FedRAMP20xEngineering — Advisory + Evidence Toolkit

**Status:** Design approved 2026-06-02. Ready for implementation planning.
**Repo:** `NPounds711/FedRAMP20xEngineering`
**Audience:** SecureIT FedRAMP advisory team and the CSP engineers they advise.

---

## 1. Purpose

A standalone repository that does two jobs for a FedRAMP engagement:

1. **Advise** — help the advisory team walk a client through the *Rev 5 vs. 20x* decision, scope the engagement, and run a gap assessment.
2. **Engineer** — give the team and the client's CSP engineers copy-and-customize **vertical slices** that produce **timestamped, hashed, chained, machine-readable evidence**, automatically **aligned to every control/KSI that evidence satisfies**, and **rendered to whatever the submission needs** (OSCAL, JSON, YAML, or human-readable).

### Guiding principles

- **Framework-agnostic evidence.** Collect a security fact once; align it to *both* the relevant 20x KSI(s) *and* the mapped NIST 800-53 Rev 5 control(s). The PMO now requires machine-readable **and** human-readable packages for **Rev 5 as well as 20x**, so the tool never has a "Rev 5 mode" vs. "20x mode" — only one evidence layer with multiple render targets. This is the core overhead reduction: the team maintains **one slice per capability**, not one per framework.
- **Deterministic evaluation.** No LLM in the evaluation path. A 3PAO can re-run the engine and get byte-identical verdicts. (Mirrors the determinism principle of the author's `grc-toolkit`.)
- **Always current.** A sync step pulls the authoritative FedRAMP sources on demand so KSI IDs, requirements, and Rev 5 baselines never drift silently.
- **Customizable templates.** Every slice ships compliant + deliberately non-compliant Terraform, OPA/Rego with tests, per-provider collectors, and a "what to edit for your environment" README so a new hire or CSP engineer can adapt it.

### Attribution

- A root `NOTICE.md` credits `GRCEngClub/claude-grc-engineering` (baseline patterns: finding-contract shape, connector ideas, the FRMR sync approach) and `FedRAMP/docs` (authoritative FRMR machine-readable policies). Patterns are adapted into our own files; there is **no hard runtime dependency** on the baseline.
- No content anywhere references the tooling used to draft the repo. Commits carry **no AI-attribution trailer**.

---

## 2. Repository layout

```
FedRAMP20xEngineering/
├─ README.md                       # what this is, who it's for, quickstart
├─ NOTICE.md                       # attribution to claude-grc-engineering + FedRAMP/docs
├─ LICENSE                         # exists
├─ docs/
│  ├─ architecture.md
│  ├─ advisory/                    # the Rev5-vs-20x advisory lens (refined seed content)
│  │  ├─ rev5-vs-20x.md
│  │  ├─ decision-guide.md         # the fit test rendered as a decision tree
│  │  ├─ methodology.md
│  │  ├─ evidence-automation-playbook.md
│  │  └─ authorization-package-checklist.md
│  └─ onboarding/                  # for new team members / CSP engineers
│     ├─ getting-started.md
│     ├─ anatomy-of-a-slice.md
│     └─ adding-a-new-slice.md
├─ gap-assessment/
│  ├─ README.md                    # how to run a 20x gap assessment + how it differs from Rev 5
│  ├─ question-bank.md             # the questions we ask, organized by KSI theme
│  └─ ksi-gap-tracker.csv          # seeded from the advisory toolkit + an Obligation column
├─ catalog/                        # synced, READ-ONLY source of truth — do not hand-edit
│  ├─ frmr/                        # FRMR.*.json from FedRAMP/docs
│  ├─ rev5/                        # FedRAMP Rev 5 OSCAL baselines
│  └─ .last-sync.json
├─ schemas/
│  ├─ finding.schema.json          # adapted from baseline (credited in NOTICE)
│  ├─ evidence-record.schema.json  # our timestamped/hashed/chained record
│  └─ slice-mapping.schema.json    # declares the KSIs + NIST controls a slice satisfies
├─ engine/
│  ├─ evidence.py                  # record_evidence(): timestamp + hash + chain
│  ├─ collect.py                   # run a slice's provider collector(s) → raw JSON
│  ├─ evaluate.py                  # OPA/Rego eval → pass/fail
│  ├─ align.py                     # attach a finding to ALL applicable KSIs + NIST controls
│  ├─ render/
│  │  ├─ oscal.py                  # OSCAL 1.2.0
│  │  ├─ json.py                   # plain machine-readable JSON
│  │  ├─ yaml.py                   # YAML variant
│  │  └─ human.py                  # human-readable narrative (md/docx) from the SAME determinations
│  ├─ report.py                    # ≥70% KSI automation coverage + required/recommended rollup + gap report
│  └─ cli.py                       # fr20x collect | evaluate | align | render | report
├─ slices/
│  ├─ _TEMPLATE/                   # copy this to add a new slice
│  │  ├─ mapping.yaml
│  │  ├─ terraform/
│  │  ├─ policy/
│  │  ├─ collectors/
│  │  └─ README.md
│  ├─ iam-mfa/
│  ├─ network-restriction/
│  └─ audit-logging-siem/
├─ tools/
│  └─ sync.py                      # pull latest FRMR + Rev 5 OSCAL baselines
└─ tests/
   └─ ...                          # pytest: evidence integrity, alignment, rego tests
```

---

## 3. The vertical slice (the core reusable unit)

One folder per security capability. This is the heart of the repo and the thing the team copies and customizes per client.

```
slices/<capability>/
├─ mapping.yaml        # KSI(s) + NIST control(s) + obligation + providers + evidence source
├─ terraform/          # compliant + deliberately non-compliant variants
├─ policy/             # OPA/Rego rules + rego tests (evaluate JSON from any provider)
├─ collectors/         # aws.py · azure.py · gcp.py · okta.py · splunk.py  (full parity per slice)
└─ README.md           # "what to edit for YOUR environment"
```

`slices/_TEMPLATE/` is the canonical copy-me starting point referenced by `docs/onboarding/adding-a-new-slice.md`.

### `mapping.yaml` shape (illustrative)

```yaml
capability: iam-mfa
title: Enforcing Phishing-Resistant MFA
ksis:
  - id: KSI-IAM-MFA
    obligation: required        # required (MUST) | recommended (SHOULD) — sourced from FRMR
nist_controls:
  - ia-2.1
  - ia-2.2
  - ia-2.8
providers: [aws, azure, gcp, okta]
evidence_source: "IdP auth-method policy + enrollment API"
rego_package: data.fr20x.iam_mfa
```

**Data flow:** `collect` (provider → raw JSON) → `evaluate` (Rego → pass/fail) → `evidence.record_evidence` (timestamp + hash + chain) → `align` (attach the determination to every KSI + NIST control in `mapping.yaml`) → `render` (OSCAL / JSON / YAML / human). One collection, both frameworks, all output formats.

---

## 4. Engine

Python (matches the author's `grc-toolkit`, the finding-schema lineage, and shells out cleanly to `opa`/`conftest`). No LLM in the evaluation path.

| Module | Responsibility |
|---|---|
| `evidence.py` | `record_evidence()` — wraps a payload with an RFC3339 UTC capture timestamp, a sha256 of the canonical payload (content integrity), a sha256 of the written file (byte integrity, `sha256sum`-verifiable), and a per-capability hash **chain** (each record references the prior record's hash) so records can't be dropped or reordered. |
| `collect.py` | Invokes a slice's provider collector(s); returns normalized raw JSON. |
| `evaluate.py` | Runs the slice's Rego against the collected JSON via `opa`/`conftest`; returns pass/fail + detail. |
| `align.py` | Reads `mapping.yaml`; attaches each determination to **all** applicable KSIs and NIST controls. Framework-agnostic — this is where "evidence supports both Rev 5 and 20x" is realized. |
| `render/oscal.py` `render/json.py` `render/yaml.py` | Machine-readable outputs. Operator chooses format per submission. |
| `render/human.py` | Human-readable narrative (markdown/docx) rendered from the **same** determination objects, so human + machine reconcile by construction (satisfies the package reconciliation gate for either framework). |
| `report.py` | Computes ≥70% KSI automation coverage, the required-vs-recommended rollup, and the gap report. |
| `cli.py` | `fr20x collect | evaluate | align | render --format oscal|json|yaml|human | report`. |

---

## 5. Sync — staying current

`tools/sync.py` pulls into a read-only `catalog/` and writes `.last-sync.json`:

- **20x:** FRMR JSON (KSI + VDR, MAS, PVA, ICP, SCN, CCM, ADS, RSC, UCM, FSI, FRD) from `github.com/FedRAMP/docs`. (The baseline's `check-fedramp-updates.js` proves this mechanism; we reimplement in Python and credit it.)
- **Rev 5:** FedRAMP Rev 5 OSCAL baselines from the FedRAMP automation repository.

The gap tracker and every `mapping.yaml` reference catalog IDs, so a FedRAMP change appears as a **sync diff** (new/changed/deprecated IDs, changed obligations) rather than silent drift. Re-sync before every engagement. Exact source URLs/paths are verified at implementation time.

---

## 6. Gap-assessment module

Formalizes the seed `methodology.md` into something the team runs.

### How a 20x gap assessment differs from Rev 5

Rev 5 asks, control by control: *"implemented and documented?"* (binary). 20x asks, per KSI, a five-axis question:

1. **Present?** Does the capability actually exist? (yes/partial/no)
2. **Automated?** Proven by automation, not assertion?
3. **Persistent?** Continuously validated, not point-in-time?
4. **Machine-readable evidence?** Emits machine output that reconciles with the narrative?
5. **Assessor-validatable?** Can a 3PAO independently confirm the *logic* (not a screenshot)?

A control can be "implemented" and still be a 20x gap if it fails axes 2–4. That automation/continuity dimension is the structural change.

### Artifacts

- `gap-assessment/README.md` — the procedure (re-sync → establish Minimum Assessment Scope incl. people/financial/third-party resources → score each KSI on five axes → classify each gap as capability/automation/continuity/evidence → compute coverage → produce a leadership readiness readout + an engineering backlog).
- `gap-assessment/question-bank.md` — the literal questions, organized by KSI theme. Example (IAM): *"Is phishing-resistant MFA enforced for all human access to in-scope resources, and can your IdP's API prove enrollment + policy state on demand?"*
- `gap-assessment/ksi-gap-tracker.csv` — seeded from the advisory toolkit (KSI ID, FKA prior IDs, theme, name, NIST control samples, automation tier, primary/alt evidence source) plus a new **Obligation** column.

Where a slice exists for a KSI, `engine/report.py` auto-fills axes 2–4 from real determinations instead of asking the question manually.

### Required vs. recommended

FRMR distinguishes **MUST (required)** from **SHOULD (recommended)**. `tools/sync.py` parses that obligation from the catalog into an `obligation` field that flows through:

- the gap tracker (`Obligation` column),
- each slice's `mapping.yaml`,
- the coverage report — reported as *required KSIs addressed %, recommended addressed %, and overall ≥70% automation*; recommendations not implemented need a documented justification (per the package checklist).

Gap output ranks **required gaps above recommended** automatically.

---

## 7. Advisory + onboarding docs

- `docs/advisory/` — the refined seed content: `rev5-vs-20x.md` (plain-language framing + the carryover/mental-model corrections), `decision-guide.md` (the fit test as a decision tree producing a Rev 5 / 20x / readiness-runway recommendation), `methodology.md`, `evidence-automation-playbook.md` (the connector-swap table for non-AWS-native clients), `authorization-package-checklist.md` (the Phase 2 hard gates).
- `docs/onboarding/` — `getting-started.md` (install, sync, run a slice end-to-end), `anatomy-of-a-slice.md`, `adding-a-new-slice.md` (copy `_TEMPLATE`, fill `mapping.yaml`, write collectors/Rego/Terraform, add tests).

---

## 8. v1 starter slices

Three, each worked across all relevant providers (full multi-cloud parity per slice). Everything else in the 60-KSI tracker becomes a tracked backlog with `_TEMPLATE` ready to fill.

| Slice | 20x KSI | Rev 5 controls | Providers |
|---|---|---|---|
| `iam-mfa` | KSI-IAM-MFA | IA-2(1)/(2)/(8) | Okta, Entra/Azure, AWS Identity Center, GCP |
| `network-restriction` | KSI-CNA-RNT | AC-17(3), SC-7(5) | AWS SG/NACL, Azure NSG, GCP firewall, k8s NetworkPolicy |
| `audit-logging-siem` | KSI-MLA-OSM | AU-2, AU-3, AU-6 | CloudTrail→Splunk, Azure Monitor→Sentinel, GCP audit logs |

`iam-mfa` builds on the author's existing MFA aggregator pattern (credited).

---

## 9. Testing

- `pytest` for the engine: evidence integrity (timestamp present, payload/file hashes verify, chain links correctly and detects reordering/drops), alignment (a determination attaches to exactly the KSIs + controls declared in `mapping.yaml`), render round-trips (machine and human outputs reconcile), and report math (coverage %, required/recommended rollup).
- Rego unit tests per slice (`opa test`) using the compliant + non-compliant Terraform fixtures — the non-compliant variant must fail, the compliant must pass.
- Schema validation of every emitted finding/evidence record against `schemas/`.

---

## 10. Git workflow

Work happens on a local clone on feature branches. **No pushes, no merges, and no AI-attribution trailer on any commit** — the repo owner performs all pushes and merges. Nothing in the repo content references the drafting tool.

---

## 11. Out of scope for v1

- Slices beyond the three starter capabilities (tracked as backlog).
- Inheritance from existing SOC 2 / ISO / Rev 4 ATOs.
- A hosted/multi-tenant SaaS surface (this repo is a runnable toolkit + template library, not a web app).
- The ~6 inherently manual KSIs (training effectiveness, executive support, after-action reports) — documented, not automated; they do not count against the ≥70% threshold.
