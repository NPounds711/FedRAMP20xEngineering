package fr20x.fixture

import rego.v1

violations contains msg if {
	input.enabled != true
	msg := "fixture resource not enabled"
}

result := {"pass": count(violations) == 0, "violations": violations}
