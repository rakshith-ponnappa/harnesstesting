/*
output "policy_assignment_id" {
  value       = module.encryption_at_host_audit.policy_assignment_id
  description = "The ID of the policy assignment"
}
*/
output "policy_assignment_name" {
  value       = module.encryption_at_host_audit.policy_assignment_name
  description = "The name of the policy assignment"
}

output "policy_definition_id" {
  value       = module.encryption_at_host_audit.policy_definition_id
  description = "The ID of the policy definition"
}

output "policy_definition_name" {
  value       = module.encryption_at_host_audit.policy_definition_name
  description = "The name of the policy definition"
}
