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
