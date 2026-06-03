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
