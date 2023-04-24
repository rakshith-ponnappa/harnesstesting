data "azurerm_subscription" "current" {}

variable "policy_definition_name" {
  type        = string
  description = "The name of the Azure Policy definition"
}

resource "azurerm_policy_definition" "encryption_at_host_policy" {
  name         = var.policy_definition_name
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Audit - Azure Virtual Machines should have encryption at host enabled"
  description  = "Ensure end-to-end encryption of a Virtual Machines Managed Disks with encryption at host: https://docs.microsoft.com/en-us/azure/virtual-machines/disk-encryption#encryption-at-host---end-to-end-encryption-for-your-vm-data"

   parameters = <<PARAMETERS
   { 
    "policyEffect": {
    "type": "String",
    "metadata": {
      "displayName": "Policy Effect",
      "description": "The effect of the policy when the conditions are met"
    },
    "allowedValues": [
      "Audit",
      "Deny",
      "Disabled"
    ],
    "defaultValue": "Audit"
  } 
  }
PARAMETERS

  policy_rule = <<POLICY_RULE
{
  "if": {
    "anyOf": [
      {
        "allOf": [
          {
            "field": "type",
            "equals": "Microsoft.Compute/virtualMachines"
          },
          {
            "field": "Microsoft.Compute/virtualMachines/securityProfile.encryptionAtHost",
            "exists": false
          }
        ]
      },
      {
        "allOf": [
          {
            "field": "type",
            "equals": "Microsoft.Compute/virtualMachineScaleSets"
          },
          {
            "field": "Microsoft.Compute/virtualMachineScaleSets/virtualMachineProfile.securityProfile.encryptionAtHost",
            "exists": false
          }
        ]
      },
      {
        "allOf": [
          {
            "field": "type",
            "equals": "Microsoft.Compute/virtualMachineScaleSets/virtualMachines"
          },
          {
            "field": "Microsoft.Compute/virtualMachineScaleSets/virtualmachines/securityProfile.encryptionAtHost",
            "exists": false
          }
        ]
      }
    ]
  },
  "then": {
    "effect": "[parameters('policyEffect')]"
  }
}
POLICY_RULE
}

resource "azurerm_policy_set_definition" "encryption_policy_set" {
  name         = "EncryptionPolicySet"
  policy_type  = "Custom"
  display_name = "Azure Virtual Machines should have encryption at host enabled"

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.encrypt_unattached_disks.id
    parameter_values = jsonencode({
      "policyEffect" = {
      "value" = "Audit"
      }
    })
  }
}

resource "azurerm_subscription_policy_assignment" "subscription_policy_assignment" {
  name                 = "${var.policy_definition_name}_assignment"
  subscription_id      = data.azurerm_subscription.current.id
  policy_definition_id = azurerm_policy_definition.encryption_at_host_policy.id
}

/*

resource "azurerm_management_group_policy_assignment" "management_group_policy_assignment" {
  name                 = "ManagementGroupPolicyAssignment"
  management_group_id  = "/providers/Microsoft.Management/managementGroups/${var.management_group_name}"
  policy_definition_id = azurerm_policy_set_definition.encryption_policy_initiative.id

  not_scopes = [
    "/subscriptions/${var.excluded_subscription_id}",
    "/subscriptions/${var.excluded_subscription_id}/resourceGroups/${var.excluded_resource_group_name}",
  ]
}

variable "management_group_name" {
  description = "The name of the management group to apply the policy assignment to."
}

variable "excluded_subscription_id" {
  description = "The ID of the subscription to exclude from the policy assignment."
}

variable "excluded_resource_group_name" {
  description = "The name of the resource group to exclude from the policy assignment."
}

*/