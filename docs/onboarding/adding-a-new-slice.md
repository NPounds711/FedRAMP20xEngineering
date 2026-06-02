# Adding a New Slice

1. **Copy the template.**
   ```bash
   cp -r slices/_TEMPLATE slices/<capability>
   ```
2. **Fill `mapping.yaml`.** Set `capability` (= folder name), the KSI id(s) and each
   `obligation` (look it up in `catalog/frmr` after `fr20x sync`), the `nist_controls`, the
   `providers` list, and `rego_package`.
3. **Write the collectors.** One `collectors/<provider>.py` per provider. Each `collect(config)`
   queries the real control plane and returns the **same normalized shape**. Accept connection
   details via `config`.
4. **Write the policy.** In `policy/policy.rego`, set the package to `rego_package`, add one
   `violations` rule per failure condition, and keep the `result` document.
5. **Write Terraform.** Make `compliant.tf` and `noncompliant.tf` real; the non-compliant one
   must trip the policy.
6. **Add a Rego test.** `policy/policy_test.rego`; run `opa test slices/<capability>/policy`.
7. **Run it end to end.**
   ```bash
   fr20x run-slice slices/<capability> --provider <provider> --run-id <id> > det.json
   fr20x render det.json --format oscal
   fr20x verify <capability>
   ```
8. **Add the KSI(s)** to the gap tracker so coverage reporting counts them.
