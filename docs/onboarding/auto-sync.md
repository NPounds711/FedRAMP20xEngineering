# FRMR auto-sync

A scheduled GitHub Actions workflow (`.github/workflows/frmr-sync.yml`) keeps the
FedRAMP reference data current. Daily it pulls `FRMR.documentation.json`, diffs it
against `catalog/FRMR.documentation.json`, and - if anything changed - refreshes the
catalog, auto-drafts safe KSI id-renames into the affected `slices/*/mapping.yaml`,
and opens a PR assigned to you. Removals, statement changes, and control-set changes
are flagged in the PR body for your decision (never auto-applied).

## One-time setup
1. **Repo setting:** Settings -> Actions -> General -> Workflow permissions -> enable
   **"Allow GitHub Actions to create and approve pull requests"**.
2. **Email secrets** (Settings -> Secrets and variables -> Actions): add `SMTP_HOST`,
   `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, and `NOTIFY_EMAIL`. (Any SMTP provider; or
   swap the email step for your provider's API.)
3. **Notifications:** keep GitHub email/mobile notifications on so the "review
   requested" ping reaches you even between emails.

## Trigger it manually
Actions -> "FRMR auto-sync" -> "Run workflow" (uses `workflow_dispatch`) to prove the
end-to-end path before relying on the daily cron.

## Local dry-run
`.venv/bin/python -m tools.frmr_drift --summary-out /tmp/s.md` prints the change
summary against the live FRMR without writing anything (omit `--apply`).
