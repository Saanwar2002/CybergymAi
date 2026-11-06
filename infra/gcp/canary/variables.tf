variable "project_id" {
  description = "Dedicated, single-purpose GCP project ID. Never use a shared or production project."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a valid lowercase GCP project ID."
  }
}

variable "region" {
  description = "Explicit region for the isolated canary subnet."
  type        = string
  default     = "europe-west2"

  validation {
    condition     = can(regex("^[a-z]+-[a-z0-9]+[0-9]$", var.region))
    error_message = "region must be an explicit GCP region, such as europe-west2."
  }
}

variable "network_name" {
  description = "Name of the dedicated custom-mode VPC."
  type        = string
  default     = "cybergym-canary"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$", var.network_name))
    error_message = "network_name must be a valid lowercase GCP resource name."
  }
}

variable "subnet_name" {
  description = "Name of the sole canary subnet."
  type        = string
  default     = "cybergym-canary"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$", var.subnet_name))
    error_message = "subnet_name must be a valid lowercase GCP resource name."
  }
}

variable "ipv4_cidr" {
  description = "Private IPv4 range for the canary subnet."
  type        = string
  default     = "10.240.0.0/24"

  validation {
    condition = alltrue([
      can(cidrnetmask(var.ipv4_cidr)),
      try(tonumber(split("/", var.ipv4_cidr)[1]), 0) >= 24,
      try(tonumber(split("/", var.ipv4_cidr)[1]), 0) <= 28,
      (
        try(tonumber(split(".", cidrhost(var.ipv4_cidr, 0))[0]), -1) == 10 ||
        (
          try(tonumber(split(".", cidrhost(var.ipv4_cidr, 0))[0]), -1) == 172 &&
          try(tonumber(split(".", cidrhost(var.ipv4_cidr, 0))[1]), -1) >= 16 &&
          try(tonumber(split(".", cidrhost(var.ipv4_cidr, 0))[1]), -1) <= 31
        ) ||
        (
          try(tonumber(split(".", cidrhost(var.ipv4_cidr, 0))[0]), -1) == 192 &&
          try(tonumber(split(".", cidrhost(var.ipv4_cidr, 0))[1]), -1) == 168
        )
      ),
      try(cidrsubnet(var.ipv4_cidr, 0, 0), "") == var.ipv4_cidr,
    ])
    error_message = "ipv4_cidr must be a canonical RFC 1918 IPv4 network between /24 and /28."
  }
}
