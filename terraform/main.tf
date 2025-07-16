###############################################################################
# Keycloak
###############################################################################

resource "keycloak_realm" "realm" {
  realm   = "HashiCorp"
  enabled = true

  access_token_lifespan       = "1h"
  client_session_idle_timeout = "1h"
  client_session_max_lifespan = "1h"
  sso_session_idle_timeout    = "1h"
  sso_session_max_lifespan    = "1h"
}

resource "keycloak_user" "user_reader" {
  realm_id = keycloak_realm.realm.id
  username = "reader"
  enabled  = true

  email      = "reader@domain.com"
  first_name = "reader"
  last_name  = "book"

  initial_password {
    value     = "reader"
    temporary = false
  }
}

resource "keycloak_user_roles" "reader_roles" {
  realm_id = keycloak_realm.realm.id
  user_id  = keycloak_user.user_reader.id

  role_ids = [
    keycloak_role.reader_role.id
  ]
}

resource "keycloak_user" "user_management" {
  realm_id = keycloak_realm.realm.id
  username = "management"
  enabled  = true

  email      = "management@domain.com"
  first_name = "management"
  last_name  = "top"

  initial_password {
    value     = "management"
    temporary = false
  }
}

resource "keycloak_user_roles" "management_roles" {
  realm_id = keycloak_realm.realm.id
  user_id  = keycloak_user.user_management.id

  role_ids = [
    keycloak_role.management_role.id
  ]
}

resource "keycloak_openid_client" "openid_client" {
  realm_id  = keycloak_realm.realm.id
  client_id = "vault-oidc"

  name                  = "vault-oidc"
  enabled               = true
  standard_flow_enabled = true

  access_type = "CONFIDENTIAL"
  valid_redirect_uris = [
    "${var.vault_url}/*",
    "http://localhost:8200/*",
    "http://127.0.0.1:8200/*",
    "http://127.0.0.1:30080/hub/oauth_callback",
    "http://127.0.0.1:8200/ui/vault/auth/keycloak-oidc/oidc/callback",
    "http://127.0.0.1:8200/ui/vault/auth/keycloak-jwt/jwt/callback",
    "urn:ietf:wg:oauth:2.0:oob"
  ]

  access_token_lifespan               = "3600"
  client_session_idle_timeout         = "3600"
  client_session_max_lifespan         = "3600"
  client_offline_session_idle_timeout = "3600"
  client_offline_session_max_lifespan = "3600"

  login_theme = "keycloak"
}

resource "keycloak_openid_user_client_role_protocol_mapper" "user_client_role_mapper" {
  realm_id  = keycloak_realm.realm.id
  client_id = keycloak_openid_client.openid_client.id
  name      = "user-client-role-mapper"
  claim_name = format("resource_access.%s.roles",
  keycloak_openid_client.openid_client.client_id)
  multivalued = true
}

resource "keycloak_openid_user_property_protocol_mapper" "preferred_username" {
  name                = "preferred_username"
  realm_id            = keycloak_realm.realm.id
  client_id           = keycloak_openid_client.openid_client.id
  user_property       = "username"
  claim_name          = "preferred_username"
  add_to_id_token     = true
  add_to_access_token = true
  add_to_userinfo     = true
}

resource "keycloak_openid_user_property_protocol_mapper" "username" {
  name                = "username"
  realm_id            = keycloak_realm.realm.id
  client_id           = keycloak_openid_client.openid_client.id
  user_property       = "username"
  claim_name          = "username"
  add_to_id_token     = true
  add_to_access_token = true
  add_to_userinfo     = true
}

resource "keycloak_role" "management_role" {
  realm_id    = keycloak_realm.realm.id
  client_id   = keycloak_openid_client.openid_client.id
  name        = "management"
  description = "Management role"
  composite_roles = [
    keycloak_role.reader_role.id
  ]
}

resource "keycloak_role" "reader_role" {
  realm_id    = keycloak_realm.realm.id
  client_id   = keycloak_openid_client.openid_client.id
  name        = "reader"
  description = "Reader role"
}

resource "vault_identity_oidc_key" "keycloak_provider_key" {
  name      = "keycloak"
  algorithm = "RS256"
}

###############################################################################
# Vault
###############################################################################

resource "vault_jwt_auth_backend" "keycloak_oidc" {
  path               = "keycloak-oidc"
  type               = "oidc"
  default_role       = "default"
  oidc_discovery_url = "http://${var.keycloak_addr}:8080/realms/${keycloak_realm.realm.id}"
  oidc_client_id     = keycloak_openid_client.openid_client.client_id
  oidc_client_secret = keycloak_openid_client.openid_client.client_secret

  tune {
    audit_non_hmac_response_keys = ["auth_url"]
    allowed_response_headers     = ["auth_url"]
    default_lease_ttl            = "1h"
    listing_visibility           = "unauth"
    max_lease_ttl                = "1h"
    passthrough_request_headers  = []
    token_type                   = "default-service"
  }
}

resource "vault_jwt_auth_backend_role" "default_oidc" {
  backend       = vault_jwt_auth_backend.keycloak_oidc.path
  role_type     = "oidc"
  role_name     = "default"
  token_ttl     = 3600
  token_max_ttl = 3600

  bound_audiences = [keycloak_openid_client.openid_client.client_id]
  user_claim      = "sub"
  claim_mappings = {
    preferred_username = "username"
    email              = "email"
  }
  allowed_redirect_uris = [
    "${var.vault_url}/ui/vault/auth/keycloak-oidc/oidc/callback",
    "http://localhost:8200/ui/vault/auth/keycloak-oidc/oidc/callback",
    "http://${var.keycloak_addr}:8250/oidc/callback",
    "http://127.0.0.1:8200/ui/vault/auth/keycloak-oidc/oidc/callback",
    "http://127.0.0.1:8200/ui/vault/auth/keycloak-jwt/jwt/callback",
    "http://127.0.0.1:30080/hub/oauth_callback",
    "urn:ietf:wg:oauth:2.0:oob"
  ]
  groups_claim = format("/resource_access/%s/roles", keycloak_openid_client.openid_client.client_id)
}

resource "vault_jwt_auth_backend" "keycloak_jwt" {
  path         = "keycloak-jwt"
  type         = "jwt"
  default_role = "default"
  jwks_url     = "http://${var.keycloak_addr}:8080/realms/${keycloak_realm.realm.id}/protocol/openid-connect/certs"

  tune {
    audit_non_hmac_request_keys  = []
    audit_non_hmac_response_keys = []
    default_lease_ttl            = "1h"
    listing_visibility           = "unauth"
    max_lease_ttl                = "1h"
    passthrough_request_headers  = []
    token_type                   = "default-service"
  }
}

resource "vault_jwt_auth_backend_role" "default_jwt" {
  backend       = vault_jwt_auth_backend.keycloak_jwt.path
  role_type     = "jwt"
  role_name     = "default"
  token_ttl     = 3600
  token_max_ttl = 3600

  bound_audiences = [keycloak_openid_client.openid_client.client_id]
  user_claim      = "sub"
  claim_mappings = {
    preferred_username = "username"
    email              = "email"
  }
  allowed_redirect_uris = [
    "${var.vault_url}/ui/vault/auth/keycloak-oidc/oidc/callback",
    "http://localhost:8200/ui/vault/auth/keycloak-oidc/oidc/callback",
    "http://${var.keycloak_addr}:8250/oidc/callback",
    "http://127.0.0.1:8200/ui/vault/auth/keycloak-oidc/oidc/callback",
    "http://127.0.0.1:8200/ui/vault/auth/keycloak-jwt/jwt/callback",
    "http://127.0.0.1:30080/hub/oauth_callback",
    "urn:ietf:wg:oauth:2.0:oob"
  ]
  groups_claim = format("/resource_access/%s/roles", keycloak_openid_client.openid_client.client_id)
}

###############################################################################
# Vault secret KV v2
###############################################################################

resource "vault_mount" "kv_v2" {
  path = "notebook-secret-kv-v2"
  type = "kv-v2"
}

resource "vault_kv_secret_v2" "secret" {
  mount = vault_mount.kv_v2.path
  name  = "test"
  data_json = jsonencode({
    data = base64encode("this is secret data")
  })
}

###############################################################################
# Vault policies
###############################################################################
module "role_policies" {
  source = "./external_group"
  external_accessors = [
    vault_jwt_auth_backend.keycloak_oidc.accessor,
    vault_jwt_auth_backend.keycloak_jwt.accessor
  ]
  vault_identity_oidc_key_name = vault_identity_oidc_key.keycloak_provider_key.name
  groups = [
    {
      group_name = "reader"
      rules = [
        {
          path         = "${vault_mount.kv_v2.path}/*"
          capabilities = ["read", "list"]
        }
      ]
    },
    {
      group_name = "management"
      rules = [
        {
          path         = "${vault_mount.kv_v2.path}/*"
          capabilities = ["read", "create", "update", "delete", "list"]
        }
      ]
    }
  ]
}



###############################################################################
# Helm
###############################################################################

resource "vault_mount" "transit" {
  path = "transit"
  type = "transit"
}

resource "vault_transit_secret_backend_key" "key" {
  backend          = vault_mount.transit.path
  name             = "my_key"
  deletion_allowed = true
}

resource "vault_generic_endpoint" "data_key" {
  path           = "${vault_mount.transit.path}/datakey/plaintext/${vault_transit_secret_backend_key.key.name}"
  data_json      = jsonencode({})
  disable_read   = true
  disable_delete = true
  write_fields   = ["plaintext"]
}

resource "helm_release" "jupyterhub" {
  name       = "jupyterhub"
  repository = "https://hub.jupyter.org/helm-chart/"
  chart      = "jupyterhub"
  version    = "4.2.0" # https://hub.jupyter.org/helm-chart/
  namespace  = "default"
  values = [
    templatefile("${path.module}/jupyterhub_values/values.yaml.tpl", {
      crypt_keeper_key = vault_generic_endpoint.data_key.write_data["plaintext"]
      client_id        = keycloak_openid_client.openid_client.client_id
      client_secret    = keycloak_openid_client.openid_client.client_secret
      callback_url     = "http://127.0.0.1:30080/hub/oauth_callback"
      authorize_url    = "http://host.minikube.internal:8080/realms/${keycloak_realm.realm.id}/protocol/openid-connect/auth"
      token_url        = "http://host.minikube.internal:8080/realms/${keycloak_realm.realm.id}/protocol/openid-connect/token"
      userdata_url     = "http://host.minikube.internal:8080/realms/${keycloak_realm.realm.id}/protocol/openid-connect/userinfo"
    })
  ]
}