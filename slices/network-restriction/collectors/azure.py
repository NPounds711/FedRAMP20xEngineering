# Azure collector for the network-restriction slice.
#
# `normalize(raw)` + helpers are pure and unit-tested. `collect(config)` lists NSG
# inbound Allow rules (lazy azure-mgmt-network + azure-identity) and maps them into
# the uniform `raw` shape. Pass {"raw": {...}} for an offline dry-run.
#
# config (live mode): {"subscription_id": "..."}
# Azure NSGs default-deny inbound (default rule DenyAllInBound, priority 65500), so
# default_deny defaults True; config may override with {"default_deny": bool}.
# Source prefixes "*", "Internet", and "0.0.0.0/0" are normalized to "0.0.0.0/0".

_ADMIN_PORTS = (22, 3389)
_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
_OPEN_SOURCES = {"*", "internet", "0.0.0.0/0", "::/0"}


def _is_open(rule):
    return rule.get("cidr") in _OPEN_CIDRS


def _covers_admin(rule):
    lo, hi = rule.get("from_port"), rule.get("to_port")
    if lo is None or hi is None:
        return True
    return any(lo <= p <= hi for p in _ADMIN_PORTS)


def _is_wide(rule, threshold=100):
    lo, hi = rule.get("from_port"), rule.get("to_port")
    if lo is None or hi is None:
        return True
    return (hi - lo) >= threshold


def _port_label(rule):
    lo, hi = rule.get("from_port"), rule.get("to_port")
    if lo is None or hi is None:
        return "all"
    return str(lo) if lo == hi else f"{lo}-{hi}"


def normalize(raw):
    rules = raw.get("rules", [])
    admin, unrestricted = [], []
    for r in rules:
        if not _is_open(r):
            continue
        entry = {"id": r["id"], "port": _port_label(r), "cidr": r["cidr"]}
        if _covers_admin(r):
            admin.append(entry)
        elif _is_wide(r):
            unrestricted.append(entry)
        # else: narrow non-admin public rule = intentional exception, not flagged
    return {
        "scope": "ingress-rules",
        "default_deny": bool(raw.get("default_deny", False)),
        "rules_evaluated": len(rules),
        "public_admin_exposures": sorted(admin, key=lambda e: e["id"]),
        "unrestricted_ingress": sorted(unrestricted, key=lambda e: e["id"]),
    }


def _port_bounds(port_range):
    # Azure destination_port_range is "*", "80", or "8000-9000".
    if port_range in ("*", None):
        return None, None
    if "-" in port_range:
        lo, hi = port_range.split("-", 1)
        return int(lo), int(hi)
    return int(port_range), int(port_range)


def collect(config):
    if "raw" in config:
        return normalize(config["raw"])
    import os

    from azure.identity import DefaultAzureCredential  # optional dep: pip install '.[azure]'
    from azure.mgmt.network import NetworkManagementClient

    sub = config.get("subscription_id") or os.environ["AZURE_SUBSCRIPTION_ID"]
    client = NetworkManagementClient(DefaultAzureCredential(), sub)

    rules = []
    for nsg in client.network_security_groups.list_all():
        for rule in (nsg.security_rules or []):
            if rule.direction != "Inbound" or rule.access != "Allow":
                continue
            source = (rule.source_address_prefix or "").lower()
            if source not in _OPEN_SOURCES:
                continue
            lo, hi = _port_bounds(rule.destination_port_range)
            rules.append({
                "id": f"{nsg.name}/{rule.name}",
                "protocol": rule.protocol,
                "from_port": lo,
                "to_port": hi,
                "cidr": "0.0.0.0/0",
            })

    default_deny = config.get("default_deny", True)
    return normalize({"default_deny": default_deny, "rules": rules})
