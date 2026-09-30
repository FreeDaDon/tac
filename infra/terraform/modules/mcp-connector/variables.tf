variable "name" {
  description = "Connector name. Lowercase letters, digits and dashes."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,62}$", var.name))
    error_message = "name must be 3-63 chars: lowercase letters, digits, dashes, starting with a letter."
  }
}

variable "connector_version" {
  description = "Exact reviewed version (semver). 'latest' and ranges are rejected."
  type        = string

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.connector_version))
    error_message = "connector_version must be an exact x.y.z version. A new version needs a new review."
  }
}

variable "environment" {
  description = "Deployment environment."
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging or prod."
  }
}

variable "server_url" {
  description = "Remote MCP endpoint. HTTPS only."
  type        = string

  validation {
    condition     = can(regex("^https://[^/]+", var.server_url)) && !can(regex("^https://(localhost|127\\.|0\\.0\\.0\\.0|\\[::1\\])", var.server_url))
    error_message = "server_url must be an https:// URL that is not a loopback address."
  }
}

variable "publisher" {
  description = "Owning team or vendor."
  type        = string
}

variable "repository" {
  description = "Source repository, for provenance."
  type        = string
}

variable "oauth_scopes" {
  description = "OAuth scopes the connector requests. Narrowest set that the tools need."
  type        = list(string)

  validation {
    condition     = length(var.oauth_scopes) > 0
    error_message = "oauth_scopes must not be empty."
  }

  validation {
    condition     = alltrue([for s in var.oauth_scopes : !can(regex("(^|[.:/_-])(\\*|admin|all|full[_-]?access|owner|root)($|[.:/_-])", lower(s)))])
    error_message = "oauth_scopes contains a wildcard or admin-class scope (mirrors MCP-SCOPE-BROAD)."
  }
}

variable "allowed_scopes" {
  description = "Scopes the IAM owner has approved for this connector. Requested scopes must be a subset (MCP-SCOPE-NOT-ALLOWED)."
  type        = list(string)
}

variable "approved_groups" {
  description = "Named IdP groups that may use the connector. Never a broad audience."
  type        = list(string)

  validation {
    condition     = length(var.approved_groups) > 0
    error_message = "approved_groups must list at least one IdP group (MCP-AUDIENCE-MISSING)."
  }

  validation {
    condition     = alltrue([for g in var.approved_groups : !contains(["*", "all", "everyone", "all employees", "public", "anyone"], lower(trimspace(g)))])
    error_message = "approved_groups must be named groups, not a broad audience (MCP-AUDIENCE-BROAD)."
  }
}

variable "tools" {
  description = "Tools the server exposes, as reviewed by a human."
  type = list(object({
    name            = string
    description     = string
    read_only       = bool
    required_scopes = list(string)
    input_schema    = optional(any, { type = "object", additionalProperties = false, properties = {} })
  }))

  validation {
    condition     = length(var.tools) > 0 && length(var.tools) <= 25
    error_message = "Declare between 1 and 25 tools (MCP-TOOL-COUNT)."
  }
}

variable "data_classification" {
  description = "Highest classification of data the connector can reach."
  type        = string

  validation {
    condition     = contains(["public", "internal", "confidential", "regulated"], var.data_classification)
    error_message = "data_classification must be public, internal, confidential or regulated."
  }
}

variable "review_ticket" {
  description = "Intake and review ticket id. Required outside dev."
  type        = string
  default     = ""
}

variable "output_dir" {
  description = "Directory where the rendered manifest and registration record are written."
  type        = string
  default     = "rendered"
}
