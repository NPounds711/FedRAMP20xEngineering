# Provider collector. One file per provider (aws.py, azure.py, gcp.py, okta.py, splunk.py).
#
# REQUIRED: expose collect(config) -> dict, returning a NORMALIZED payload whose shape is
# identical across every provider for this slice — so the single Rego policy can evaluate
# all of them. Do NOT leak provider-specific field names into the payload.
#
# WHAT TO EDIT FOR YOUR ENVIRONMENT:
#   - Replace the body with real calls (boto3 / Azure SDK / google-cloud / Okta REST / Splunk API).
#   - Accept connection details via `config` (region, account, tenant, token env var name, etc.).
#   - Keep the return shape stable; the Rego in policy/policy.rego depends on it.
def collect(config):
    # Example normalized shape — replace values with real queried state:
    return {
        "resource_id": config.get("resource_id", "REPLACE-ME"),
        "compliant_flag": False,  # <-- compute this from the real control-plane response
    }
