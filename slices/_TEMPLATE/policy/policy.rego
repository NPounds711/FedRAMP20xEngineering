# Source-agnostic policy: evaluates the NORMALIZED payload from any provider collector.
# The package name MUST match `rego_package` in mapping.yaml.
package fr20x.template_capability

import rego.v1

# Add one rule per failure condition. Each adds a human-readable violation string.
violations contains msg if {
	input.compliant_flag != true
	msg := "resource is not in the compliant state"
}

# REQUIRED decision document consumed by the engine. Do not rename.
result := {"pass": count(violations) == 0, "violations": violations}
