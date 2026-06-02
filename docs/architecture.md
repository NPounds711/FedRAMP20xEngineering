# Architecture

## Pipeline
```
collect -> record_evidence -> evaluate -> align -> render
  |            |                 |          |        +- oscal | json | yaml | human
  |            |                 |          +- attach the determination to all 20x KSIs + Rev 5 controls
  |            |                 +- OPA/Rego over the normalized payload -> {pass, violations}
  |            +- RFC3339 timestamp + payload sha256 + file sha256 + per-capability hash chain
  +- per-provider collector returns a normalized payload (same shape across providers)
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
sha256 and the prior record's hash. `fr20x verify <capability>` re-hashes the record bytes,
recomputes each record hash, and checks the chain linkage, detecting tampering, field edits, or
reordering. Known limitation: it does not detect truncation of the chain's tail (no terminal
seal yet).

## Determinism
`canonical_json` sorts keys and removes whitespace; OSCAL UUIDs are uuid5-derived. Given the same
inputs, every output is byte-identical — a property a 3PAO can rely on.
