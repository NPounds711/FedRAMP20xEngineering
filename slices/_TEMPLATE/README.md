# Slice: <capability>

> Copy this folder to `slices/<your-capability>/` and work top-to-bottom.

## What this slice proves
One sentence: the security capability, the 20x KSI(s), and the Rev 5 control(s) it satisfies.

## Files and what to edit
| File | Edit |
|---|---|
| `mapping.yaml` | KSI id(s) + obligation, NIST controls, providers, `rego_package`. |
| `collectors/<provider>.py` | `collect(config)` -> normalized payload (same shape for every provider). |
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
