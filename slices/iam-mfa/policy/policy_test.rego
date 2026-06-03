package fr20x.iam_mfa_test

import rego.v1

import data.fr20x.iam_mfa

compliant := {
	"subject_scope": "all-human-users",
	"mfa_required_by_policy": true,
	"phishing_resistant_required_by_policy": true,
	"users_evaluated": 3,
	"users_without_mfa": [],
	"users_with_non_phishing_resistant_mfa": [],
}

noncompliant := {
	"subject_scope": "all-human-users",
	"mfa_required_by_policy": false,
	"phishing_resistant_required_by_policy": false,
	"users_evaluated": 3,
	"users_without_mfa": ["bob@example.com"],
	"users_with_non_phishing_resistant_mfa": ["carol@example.com"],
}

test_compliant_passes if {
	iam_mfa.result.pass with input as compliant
}

test_noncompliant_fails if {
	not iam_mfa.result.pass with input as noncompliant
}

test_all_four_violations_fire if {
	count(iam_mfa.result.violations) == 4 with input as noncompliant
}
