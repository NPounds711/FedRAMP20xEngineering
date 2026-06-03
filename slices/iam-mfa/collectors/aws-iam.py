# AWS classic-IAM collector for the iam-mfa slice.
#
# Unlike the `aws` collector (which queries Identity Center / identitystore), this
# collector queries classic IAM users (iam:ListUsers + iam:ListMFADevices). Use the
# provider name `aws-iam`. `normalize(raw)` is pure and unit-tested; `collect(config)`
# does live IAM calls (lazy `boto3`) and a {"raw": {...}} offline dry-run seam.
#
# config (live mode): {} (uses the ambient AWS credentials/region; supply
#   {"policy": {"mfa_required": bool, "phishing_resistant_required": bool}} since classic
#   IAM has no single policy flag to read).
#
# Phishing-resistant = FIDO security keys (serial carries a 'u2f'/'fido' marker).
# Virtual TOTP and hardware OTP tokens are NOT phishing-resistant.

_PHISHING_RESISTANT = {"fido", "u2f", "webauthn"}


def _factor_label(serial):
    """Map an IAM MFA device serial to a normalized factor label. FIDO/security-key
    serials carry a 'u2f' marker; virtual TOTP and hardware OTP map to 'virtual'."""
    s = (serial or "").lower()
    if "u2f" in s or "fido" in s:
        return "fido"
    return "virtual"


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

    iam = boto3.client("iam")
    users = []
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for u in page["Users"]:
            devices = iam.list_mfa_devices(UserName=u["UserName"]).get("MFADevices", [])
            factors = [_factor_label(d.get("SerialNumber", "")) for d in devices]
            users.append({
                "id": u["UserName"],
                "status": "ACTIVE",
                "type": "human",
                "factors": factors,
            })
    # classic IAM has no single 'MFA required' flag; supply enforcement via config.
    pol = config.get("policy", {"mfa_required": False, "phishing_resistant_required": False})
    return normalize({"policy": pol, "users": users})
