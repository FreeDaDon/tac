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
  description = "Remote MCP endpoint. HTTPS to a DNS hostname only: no IP literal, no userinfo, no loopback or metadata host, in any environment."
  type        = string

  # The host must be dotted DNS labels ending in a TLD that starts with a letter. That rejects every IP literal
  # (dotted, decimal 2130706433, hex, octal, IPv6 brackets), so 127/8, 10/8, 172.16/12, 192.168/16 and 169.254/16
  # cannot be reached by address, and a user@ prefix cannot hide the real host.
  validation {
    condition     = can(regex("^https://([a-z0-9]([a-z0-9-]*[a-z0-9])?\\.)+[a-z]([a-z0-9-]*[a-z0-9])?(:[0-9]{1,5})?([/?#][^\\s]*)?$", lower(var.server_url)))
    error_message = "server_url must be https:// followed by a dotted DNS hostname (no IP literal, no user@ part, no bare single-label host), then an optional port and path (mirrors MCP-TRANSPORT-PLAINTEXT)."
  }

  validation {
    condition     = !can(regex("^https://([a-z0-9.-]+\\.)?(localhost|localhost\\.localdomain|metadata\\.google\\.internal)([:/?#]|$)", lower(var.server_url)))
    error_message = "server_url must not name a loopback or cloud metadata host."
  }
}

variable "publisher" {
  description = "Owning team or vendor."
  type        = string
}

variable "repository" {
  description = "Source repository, for provenance. HTTPS, with no credentials in the URL."
  type        = string

  validation {
    condition     = can(regex("^https://([a-z0-9]([a-z0-9-]*[a-z0-9])?\\.)+[a-z]([a-z0-9-]*[a-z0-9])?(:[0-9]{1,5})?/[^\\s?#]+$", lower(var.repository)))
    error_message = "repository must be an https:// URL with a DNS host and a path, and no user@ credentials."
  }
}

variable "oauth_scopes" {
  description = "OAuth scopes the connector requests. Narrowest set that the tools need."
  type        = list(string)

  validation {
    condition     = length(var.oauth_scopes) > 0
    error_message = "oauth_scopes must not be empty."
  }

  validation {
    condition     = alltrue([for s in var.oauth_scopes : !strcontains(s, "*")])
    error_message = "oauth_scopes must not contain a wildcard anywhere (mirrors MCP-SCOPE-BROAD)."
  }

  validation {
    condition     = alltrue([for s in var.oauth_scopes : !can(regex("(^|[.:/_-])(admin|administrator|all|full[_-]?access|owner|root|superuser)($|[.:/_-])|(^|[.:/_-])cloud-platform/?$|(^|/)\\.default$", lower(trimspace(s))))])
    error_message = "oauth_scopes contains an admin-class scope, cloud-platform, or a Graph .default scope (mirrors MCP-SCOPE-BROAD)."
  }

  validation {
    condition     = alltrue([for s in var.oauth_scopes : !contains(["https://mail.google.com", "https://www.googleapis.com/auth/drive"], trimsuffix(lower(trimspace(s)), "/"))])
    error_message = "oauth_scopes contains a whole-account scope (full Gmail or full Drive) (mirrors MCP-SCOPE-BROAD)."
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
  description = "Tools the server exposes, as reviewed by a human. input_schema is a JSON string (use jsonencode) so tools can carry differently shaped schemas."
  type = list(object({
    name            = string
    description     = string
    read_only       = bool
    open_world      = optional(bool, true)
    required_scopes = list(string)
    input_schema    = optional(string, "{\"type\":\"object\",\"additionalProperties\":false,\"properties\":{}}")
  }))

  validation {
    condition     = length(var.tools) > 0 && length(var.tools) <= 25
    error_message = "Declare between 1 and 25 tools (MCP-TOOL-COUNT)."
  }

  validation {
    condition     = length(distinct([for t in var.tools : t.name])) == length(var.tools)
    error_message = "Tool names must be unique."
  }

  validation {
    condition     = alltrue([for t in var.tools : try(jsondecode(t.input_schema).type == "object" && jsondecode(t.input_schema).additionalProperties == false, false)])
    error_message = "Each tool's input_schema must be a JSON object schema with \"type\": \"object\" and \"additionalProperties\": false."
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
  description = "Intake and review ticket id (AICR-<number>). Required outside dev."
  type        = string
  default     = ""

  validation {
    condition     = var.review_ticket == "" || can(regex("^AICR-[1-9][0-9]*$", var.review_ticket))
    error_message = "review_ticket must be a real AICR-<number> ticket. Placeholders such as AICR-0000 are rejected."
  }
}

variable "output_dir" {
  description = "Directory where the rendered manifest and registration record are written."
  type        = string
  default     = "rendered"
}
