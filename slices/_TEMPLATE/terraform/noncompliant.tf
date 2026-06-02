# A DELIBERATELY non-compliant variant, so the policy can be SEEN to catch a violation.
# Apply in a throwaway environment to prove the Rego fails as expected.
#
# WHAT TO EDIT: mirror compliant.tf but flip the setting(s) that violate the control.
# resource "example_resource" "noncompliant" {
#   secure_setting = false
# }
