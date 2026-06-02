# Anatomy of a Slice

A slice is a self-contained vertical for one security capability:

```
slices/<capability>/
  mapping.yaml      # KSI(s) + obligation, NIST controls, providers, rego_package
  collectors/       # one file per provider; each collect(config) -> NORMALIZED payload
  policy/           # OPA/Rego over the normalized payload -> {pass, violations}
  terraform/        # compliant.tf + noncompliant.tf (prove the policy catches violations)
  README.md         # what to edit for this slice
```

## The contracts that make it work
- **Normalized payload.** Every collector for a slice returns the same shape, so one policy
  evaluates all providers. Never leak provider-specific field names into the payload.
- **Rego result document.** The policy defines `result := {"pass": <bool>, "violations": [...]}`
  under the package named in `mapping.yaml`. The engine reads exactly that.
- **One fact, both frameworks.** `mapping.yaml` lists the 20x KSI(s) and the Rev 5 control(s)
  the same evidence satisfies; `align` attaches both automatically.

## Data flow for one run
`collect` (provider -> normalized JSON) -> `record_evidence` (timestamp + hash + chain) ->
`evaluate` (Rego -> pass/fail) -> `align` (-> determination with both frameworks) ->
`render` (OSCAL/JSON/YAML/human). The human and machine renders come from the same
determination object, so they reconcile by construction.
