#------------------------------------------------------------------------------#
# Vault policy
#------------------------------------------------------------------------------#

data "vault_policy_document" "policy" {
  count = length(var.groups)

  dynamic "rule" {
    for_each = var.groups[count.index].rules
    content {
      path         = rule.value.path
      capabilities = rule.value.capabilities
    }
  }
}

resource "vault_policy" "policy" {
  count  = length(var.groups)
  name   = var.groups[count.index].group_name
  policy = data.vault_policy_document.policy[count.index].hcl
}

#------------------------------------------------------------------------------#
# Vault external group
#------------------------------------------------------------------------------#

resource "vault_identity_oidc_role" "role" {
  count = length(var.groups)
  name  = var.groups[count.index].group_name
  key   = var.vault_identity_oidc_key_name
}

resource "vault_identity_group" "group" {
  count = length(var.groups)
  name  = vault_identity_oidc_role.role[count.index].name
  type  = "external"
  policies = [
    vault_policy.policy[count.index].name
  ]
}

# 각 auth backend별로 별도 처리하여 의존성 문제 해결
locals {
  # 모든 조합을 미리 계산
  group_accessor_combinations = flatten([
    for group_idx, group in var.groups : [
      for accessor_idx, accessor in var.external_accessors : {
        group_idx    = group_idx
        accessor_idx = accessor_idx
        group_name   = group.group_name
        accessor     = accessor
      }
    ]
  ])
}

resource "vault_identity_group_alias" "group_alias" {
  count = length(local.group_accessor_combinations)
  
  name           = local.group_accessor_combinations[count.index].group_name
  mount_accessor = local.group_accessor_combinations[count.index].accessor
  canonical_id   = vault_identity_group.group[local.group_accessor_combinations[count.index].group_idx].id
}