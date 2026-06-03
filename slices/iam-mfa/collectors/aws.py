# AWS IAM Identity Center collector for the iam-mfa slice.
#
# `normalize(raw)` is pure and unit-tested. `collect(config)` queries Identity Store
# (lazy `boto3`). Pass {"raw": {...}} for an offline dry-run.
#
# config (live mode):
#   {"identity_store_id": "d-1234567890", "region": "us-gov-west-1"}
# "factors" holds Identity Center MFA device types (e.g. "WebAuthn", "TOTP", "SMS").

_PHISHING_RESISTANT = {"WebAuthn"}


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
    import boto3  # optional dep: pip install '.[aws]'

    store_id = config["identity_store_id"]
    ids = boto3.client("identitystore", region_name=config.get("region"))

    users = []
    paginator = ids.get_paginator("list_users")
    for page in paginator.paginate(IdentityStoreId=store_id):
        for u in page["Users"]:
            devices = ids.list_mfa_devices(
                IdentityStoreId=store_id, MemberId={"UserId": u["UserId"]}
            ).get("MFADevices", [])
            users.append({
                "id": u.get("UserName", u["UserId"]),
                "status": "ACTIVE",
                "type": "human",
                "factors": [d.get("DeviceType", "Unknown") for d in devices],
            })

    pol = config.get("policy", {"mfa_required": False, "phishing_resistant_required": False})
    return normalize({"policy": pol, "users": users})
