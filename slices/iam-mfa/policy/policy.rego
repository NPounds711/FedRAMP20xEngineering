# Provider-agnostic MFA policy. Evaluates the normalized payload emitted identically
# by every collector in collectors/. Package MUST match mapping.yaml `rego_package`.
package fr20x.iam_mfa

import rego.v1

violations contains msg if {
	input.mfa_required_by_policy != true
	msg := "MFA is not enforced by policy for human users (IA-2(1)/(2))"
}

violations contains msg if {
	input.phishing_resistant_required_by_policy != true
	msg := "policy does not require phishing-resistant MFA (IA-2(8))"
}

violations contains msg if {
	count(input.users_without_mfa) > 0
	msg := sprintf("%d human user(s) without any MFA: %v", [count(input.users_without_mfa), input.users_without_mfa])
}

violations contains msg if {
	count(input.users_with_non_phishing_resistant_mfa) > 0
	msg := sprintf("%d human user(s) using non-phishing-resistant MFA: %v", [count(input.users_with_non_phishing_resistant_mfa), input.users_with_non_phishing_resistant_mfa])
}

# REQUIRED decision document consumed by the engine. Do not rename.
result := {"pass": count(violations) == 0, "violations": violations}
