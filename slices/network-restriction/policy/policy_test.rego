package fr20x.network_restriction_test

import rego.v1

import data.fr20x.network_restriction

compliant := {
	"scope": "ingress-rules",
	"default_deny": true,
	"rules_evaluated": 3,
	"public_admin_exposures": [],
	"unrestricted_ingress": [],
}

noncompliant := {
	"scope": "ingress-rules",
	"default_deny": false,
	"rules_evaluated": 3,
	"public_admin_exposures": [{"id": "sg-a/tcp/0", "port": "22", "cidr": "0.0.0.0/0"}],
	"unrestricted_ingress": [{"id": "sg-a/tcp/4", "port": "8000-9000", "cidr": "0.0.0.0/0"}],
}

test_compliant_passes if {
	network_restriction.result.pass with input as compliant
}

test_noncompliant_fails if {
	not network_restriction.result.pass with input as noncompliant
}

test_all_three_violations_fire if {
	count(network_restriction.result.violations) == 3 with input as noncompliant
}
