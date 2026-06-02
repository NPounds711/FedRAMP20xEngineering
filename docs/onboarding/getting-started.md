# Getting Started

For a new team member or a CSP engineer. Assumes Python 3.12 and git.

## 1. Install
```bash
python3.12 -m venv .venv && . .venv/bin/activate
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

## Troubleshooting
- **`fr20x: No module named 'engine'` when run from outside the repo (macOS):** macOS can set a
  hidden flag on files inside `.venv`, which makes the editable-install path file get skipped.
  Fix with `chflags -R nohidden .venv/lib/python*/site-packages/`, or just run `fr20x` from the
  repo root. Re-running `pip install -e .` may reintroduce the flag.

## Next
Read `anatomy-of-a-slice.md`, then `adding-a-new-slice.md`.
