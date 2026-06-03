# Google Workspace collector for the iam-mfa slice.
#
# `normalize(raw)` is pure and unit-tested. `collect(config)` calls the Admin SDK
# Directory API (lazy google-api-python-client). Pass {"raw": {...}} for an offline
# dry-run.
#
# config (live mode):
#   {"customer": "my_customer", "delegated_admin": "admin@example.com",
#    "sa_key_env": "GOOGLE_SA_KEY_FILE"}
# "factors" is derived per user: SECURITY_KEY when a hardware key is enrolled,
# else the weakest enrolled 2SV method (GOOGLE_PROMPT / TOTP / SMS / BACKUP_CODE).

_PHISHING_RESISTANT = {"SECURITY_KEY"}


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

    from google.oauth2 import service_account  # optional dep: pip install '.[gcp]'
    from googleapiclient.discovery import build

    creds = service_account.Credentials.from_service_account_file(
        os.environ[config.get("sa_key_env", "GOOGLE_SA_KEY_FILE")],
        scopes=["https://www.googleapis.com/auth/admin.directory.user.readonly"],
        subject=config["delegated_admin"],
    )
    service = build("admin", "directory_v1", credentials=creds)

    users = []
    page_token = None
    while True:
        resp = service.users().list(
            customer=config.get("customer", "my_customer"),
            maxResults=200, pageToken=page_token, projection="full",
        ).execute()
        for u in resp.get("users", []):
            if not u.get("isEnrolledIn2Sv"):
                factors = []
            elif u.get("isEnforcedIn2Sv"):
                # Admin SDK does not expose the exact 2SV factor; security-key
                # enforcement is supplied via config.security_key_users allowlist.
                factors = ["SECURITY_KEY"] if u.get("primaryEmail") in config.get(
                    "security_key_users", []) else ["GOOGLE_PROMPT"]
            else:
                factors = ["GOOGLE_PROMPT"]
            users.append({
                "id": u["primaryEmail"],
                "status": "ACTIVE" if not u.get("suspended") else "SUSPENDED",
                "type": "human",
                "factors": factors,
            })
        page_token = resp.get("nextPageToken")
        if not page_token:
            break

    pol = config.get("policy", {"mfa_required": False, "phishing_resistant_required": False})
    return normalize({"policy": pol, "users": users})
