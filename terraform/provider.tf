terraform {
  required_version = ">= 1.0"

  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = ">= 5.0.0"
    }
    keycloak = {
      source  = "keycloak/keycloak"
      version = ">= 5.0.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 3.0.0"
    }
  }
}

variable "vault_url" {
  type    = string
  default = "http://127.0.0.1:8200"
}
variable "keycloak_addr" {
  type    = string
  default = "127.0.0.1"
}

locals {
  vault_root_token  = "root"
  keycloak_user     = "admin"
  keycloak_password = "password"
}

provider "vault" {
  address = var.vault_url
  token   = local.vault_root_token
}

provider "keycloak" {
  client_id = "admin-cli"
  username  = local.keycloak_user
  password  = local.keycloak_password
  url       = "http://${var.keycloak_addr}:8080"
}

provider "helm" {
  kubernetes = {
    config_context = "minikube"
    config_path    = "~/.kube/config"
  }
}