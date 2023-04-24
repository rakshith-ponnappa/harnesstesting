provider "azurerm" {
  features {}
}

data "azurerm_subscription" "current" {}

module "encryption_at_host_audit" {
  source               = "./encryption_at_host_audit_module"
  #subscription_id      =  data.azurerm_subscription.current.id
  policy_definition_name = "encryption_at_host_audit"
}
