# Microsoft Entra (Azure AD) collector for the iam-mfa slice.
#
# `normalize(raw)` is pure and unit-tested. `collect(config)` calls Microsoft Graph
# (lazy `msgraph-sdk`). Pass {"raw": {...}} for an offline dry-run.
#
# config (live mode):
#   {"tenant_id": "...", "client_id": "...", "client_secret_env": "ENTRA_CLIENT_SECRET"}
# "factors" holds Graph authentication-method @odata.type short names.
# Only "human" members are evaluated; guests are excluded.

_PHISHING_RESISTANT = {"fido2", "windowsHelloForBusiness", "x509Certificate"}


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
    import asyncio
    import os

    from azure.identity import ClientSecretCredential  # optional dep: pip install '.[entra]'
    from msgraph import GraphServiceClient

    cred = ClientSecretCredential(
        tenant_id=config["tenant_id"],
        client_id=config["client_id"],
        client_secret=os.environ[config.get("client_secret_env", "ENTRA_CLIENT_SECRET")],
    )
    client = GraphServiceClient(cred)

    async def _gather():
        rows = []
        users = await client.users.get()
        for u in users.value:
            if u.user_type and u.user_type.lower() == "guest":
                continue
            methods = await client.users.by_user_id(u.id).authentication.methods.get()
            factors = [
                (m.odata_type or "").rsplit(".", 1)[-1].replace("AuthenticationMethod", "")
                for m in methods.value
            ]
            rows.append({
                "id": u.user_principal_name or u.id,
                "status": "ACTIVE" if (u.account_enabled is not False) else "DISABLED",
                "type": "human",
                "factors": [f for f in factors if f],
            })
        return rows

    users = asyncio.run(_gather())
    pol = config.get("policy", {"mfa_required": False, "phishing_resistant_required": False})
    return normalize({"policy": pol, "users": users})
