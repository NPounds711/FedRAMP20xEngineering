# Okta collector for the iam-mfa slice.
#
# Returns the normalized payload shared by every iam-mfa collector. `normalize(raw)`
# is pure and unit-tested; `collect(config)` does the live Okta REST calls (lazy
# `requests` import) and then normalizes. Pass {"raw": {...}} in config for an
# offline dry-run.
#
# config (live mode):
#   {"okta_domain": "example.okta.com", "token_env": "OKTA_API_TOKEN"}
# A user's "factors" is the list of enrolled Okta factorType strings.

_PHISHING_RESISTANT = {"webauthn", "u2f"}


def normalize(raw):
    users = [
        u for u in raw.get("users", [])
        if u.get("type", "human") == "human"
        and str(u.get("status", "ACTIVE")).upper() == "ACTIVE"
    ]
    without, weak = [], []
    for u in users:
        factors = u.get("factors", [])
        if not factors:
            without.append(u["id"])
        elif not any(f in _PHISHING_RESISTANT for f in factors):
            weak.append(u["id"])
    pol = raw.get("policy", {})
    return {
        "subject_scope": "all-human-users",
        "mfa_required_by_policy": bool(pol.get("mfa_required", False)),
        "phishing_resistant_required_by_policy": bool(pol.get("phishing_resistant_required", False)),
        "users_evaluated": len(users),
        "users_without_mfa": sorted(without),
        "users_with_non_phishing_resistant_mfa": sorted(weak),
    }


def collect(config):
    if "raw" in config:
        return normalize(config["raw"])
    import os

    import requests  # optional dep: pip install '.[okta]'

    domain = config["okta_domain"]
    token = os.environ[config.get("token_env", "OKTA_API_TOKEN")]
    headers = {"Authorization": f"SSWS {token}", "Accept": "application/json"}
    base = f"https://{domain}/api/v1"

    users = []
    url = f"{base}/users?filter=status eq \"ACTIVE\"&limit=200"
    while url:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        for u in resp.json():
            f = requests.get(f"{base}/users/{u['id']}/factors", headers=headers, timeout=30)
            f.raise_for_status()
            users.append({
                "id": u["profile"].get("login", u["id"]),
                "status": u["status"],
                "type": "human",
                "factors": [fac["factorType"] for fac in f.json()],
            })
        url = resp.links.get("next", {}).get("url")

    # Policy enforcement is supplied via config (derive from your Okta global session
    # / authenticator enrollment policy); Okta's API does not expose a single boolean.
    pol = config.get("policy", {"mfa_required": False, "phishing_resistant_required": False})
    return normalize({"policy": pol, "users": users})
