# AWS collector for the network-restriction slice.
#
# `normalize(raw)` + the classification helpers are pure and unit-tested. `collect(config)`
# queries EC2 security groups (lazy `boto3`) and maps them into the uniform `raw` shape,
# then normalizes. Pass {"raw": {...}} for an offline dry-run.
#
# config (live mode): {"region": "us-gov-west-1"}
# default_deny is derived as: the VPC default security group has no ingress rules
# (AWS security groups are implicitly deny-by-default; an empty default SG is the
# best-practice signal). config may override with {"default_deny": bool}.

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
    import boto3  # optional dep: pip install '.[aws]'

    ec2 = boto3.client("ec2", region_name=config.get("region"))
    groups = ec2.describe_security_groups()["SecurityGroups"]

    rules = []
    default_has_ingress = False
    for sg in groups:
        for i, perm in enumerate(sg.get("IpPermissions", [])):
            proto = str(perm.get("IpProtocol", "-1"))
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            cidrs = [r["CidrIp"] for r in perm.get("IpRanges", [])]
            cidrs += [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])]
            for j, cidr in enumerate(cidrs):
                rules.append({
                    "id": f"{sg['GroupId']}/{proto}/{i}-{j}",
                    "protocol": proto,
                    "from_port": from_port,
                    "to_port": to_port,
                    "cidr": cidr,
                })
        if sg.get("GroupName") == "default" and sg.get("IpPermissions"):
            default_has_ingress = True

    default_deny = config.get("default_deny", not default_has_ingress)
    return normalize({"default_deny": default_deny, "rules": rules})
