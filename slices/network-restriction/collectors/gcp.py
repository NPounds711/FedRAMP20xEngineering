# GCP collector for the network-restriction slice.
#
# `normalize(raw)` + helpers are pure and unit-tested. `collect(config)` lists VPC
# firewall rules (lazy google-cloud-compute) and maps INGRESS allow rules open to
# 0.0.0.0/0 into the uniform `raw` shape. Pass {"raw": {...}} for an offline dry-run.
#
# config (live mode): {"project": "my-project"}
# GCP VPC networks have an implied deny-all ingress, so default_deny defaults True;
# config may override with {"default_deny": bool}. A firewall "allowed" entry with
# no ports (e.g. protocol "all" or "icmp") maps to from/to_port = None (all-traffic).

_ADMIN_PORTS = (22, 3389)
_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def _is_open(rule):
    return rule.get("cidr") in _OPEN_CIDRS


def _covers_admin(rule):
    lo, hi = rule.get("from_port"), rule.get("to_port")
    if lo is None or hi is None:          # all-traffic rule
        return True
    return any(lo <= p <= hi for p in _ADMIN_PORTS)


def _is_wide(rule, threshold=100):
    lo, hi = rule.get("from_port"), rule.get("to_port")
    if lo is None or hi is None:          # all-traffic rule
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


def collect(config):
    if "raw" in config:
        return normalize(config["raw"])
    from google.cloud import compute_v1  # optional dep: pip install '.[gcp]'

    project = config["project"]
    client = compute_v1.FirewallsClient()

    rules = []
    for fw in client.list(project=project):
        if fw.direction != "INGRESS" or not fw.allowed:
            continue
        if "0.0.0.0/0" not in list(fw.source_ranges):
            continue
        for allowed in fw.allowed:
            ports = list(allowed.ports) if allowed.ports else []
            if not ports:
                lo = hi = None
            else:
                first = ports[0]
                if "-" in first:
                    a, b = first.split("-", 1)
                    lo, hi = int(a), int(b)
                else:
                    lo = hi = int(first)
            rules.append({
                "id": fw.name,
                "protocol": allowed.I_p_protocol,
                "from_port": lo,
                "to_port": hi,
                "cidr": "0.0.0.0/0",
            })

    default_deny = config.get("default_deny", True)
    return normalize({"default_deny": default_deny, "rules": rules})
