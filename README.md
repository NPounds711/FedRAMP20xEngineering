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
python3.12 -m venv .venv && . .venv/bin/activate
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
- `engine/` — collect -> record -> evaluate -> align -> render -> report.
- `tools/sync.py` — pull the latest FRMR catalog from `FedRAMP/docs`.
- `catalog/` — synced, read-only source of truth.

See `docs/architecture.md` and `docs/onboarding/`. Attribution is in `NOTICE.md`.
