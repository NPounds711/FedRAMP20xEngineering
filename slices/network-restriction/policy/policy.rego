# Provider-agnostic network-restriction policy. Evaluates the normalized payload
# emitted identically by every collector. Package MUST match mapping.yaml `rego_package`.
package fr20x.network_restriction

import rego.v1

violations contains msg if {
	input.default_deny != true
	msg := "default-deny network posture is not enforced (SC-7(5))"
}

violations contains msg if {
	count(input.public_admin_exposures) > 0
	ids := [e.id | some e in input.public_admin_exposures]
	msg := sprintf("%d rule(s) expose an admin port to the internet, bypassing managed access points (AC-17(3)): %v", [count(input.public_admin_exposures), ids])
}

violations contains msg if {
	count(input.unrestricted_ingress) > 0
	ids := [e.id | some e in input.unrestricted_ingress]
	msg := sprintf("%d rule(s) allow unrestricted internet ingress instead of allow-by-exception (SC-7(5)): %v", [count(input.unrestricted_ingress), ids])
}

# REQUIRED decision document consumed by the engine. Do not rename.
result := {"pass": count(violations) == 0, "violations": violations}
