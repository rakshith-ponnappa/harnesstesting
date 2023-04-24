

output "policy_assignment_name" {
  value       = azurerm_subscription_policy_assignment.subscription_policy_assignment.name
}
output "policy_definition_name" {
  value       = azurerm_policy_definition.encryption_at_host_policy.name
}

