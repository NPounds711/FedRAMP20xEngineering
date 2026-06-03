import importlib.util
from pathlib import Path

COLLECTOR = Path(__file__).resolve().parent.parent / "slices" / "network-restriction" / "collectors" / "aws.py"


def _load():
    spec = importlib.util.spec_from_file_location("netr_aws_dd", COLLECTOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# AWS describe_security_groups-shaped fixtures
def _default_sg(perms):
    return {"GroupName": "default", "GroupId": "sg-default", "IpPermissions": perms}


def test_self_referencing_default_sg_is_still_deny_by_default():
    aws = _load()
    # the benign default self-reference: source is the SG itself, NO CIDR ranges
    self_ref = {"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": "sg-default"}],
                "IpRanges": [], "Ipv6Ranges": []}
    groups = [_default_sg([self_ref]), {"GroupName": "web", "GroupId": "sg-web", "IpPermissions": []}]
    assert aws._derive_default_deny(groups) is True


def test_default_sg_with_external_cidr_is_not_deny_by_default():
    aws = _load()
    open_rule = {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                 "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}
    groups = [_default_sg([open_rule])]
    assert aws._derive_default_deny(groups) is False


def test_default_sg_with_ipv6_cidr_is_not_deny_by_default():
    aws = _load()
    open6 = {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
             "IpRanges": [], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}
    groups = [_default_sg([open6])]
    assert aws._derive_default_deny(groups) is False


def test_no_default_sg_present_defaults_to_deny():
    aws = _load()
    groups = [{"GroupName": "web", "GroupId": "sg-web", "IpPermissions": []}]
    assert aws._derive_default_deny(groups) is True
