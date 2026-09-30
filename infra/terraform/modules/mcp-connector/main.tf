locals {
  tool_scopes = toset(flatten([for t in var.tools : t.required_scopes]))

  # Same shape core/mcp_gov/manifest.py reads, so the scanner can gate the rendered file in CI.
  manifest = {
    name       = var.name
    version    = var.connector_version
    transport  = "https"
    url        = var.server_url
    repository = var.repository
    publisher  = var.publisher
    auth = {
      type   = "oauth2"
      flow   = "authorization_code"
      pkce   = true
      scopes = sort(var.oauth_scopes)
    }
    governance = {
      approved_groups = sort(var.approved_groups)
    }
    tools = [for t in var.tools : {
      name           = t.name
      description    = t.description
      annotations    = { readOnlyHint = t.read_only, openWorldHint = false }
      requiredScopes = t.required_scopes
      inputSchema    = t.input_schema
    }]
  }

  manifest_json = jsonencode(local.manifest)

  registration = {
    environment         = var.environment
    data_classification = var.data_classification
    review_ticket       = var.review_ticket
    manifest_sha256     = sha256(local.manifest_json)
    approved_groups     = sort(var.approved_groups)
  }
}

# Cross-variable rules that a single variable validation cannot express.
resource "terraform_data" "guard" {
  input = local.manifest_json

  lifecycle {
    precondition {
      condition     = length(setsubtract(toset(var.oauth_scopes), toset(var.allowed_scopes))) == 0
      error_message = "Requested scopes exceed the approved allowlist: ${join(", ", setsubtract(toset(var.oauth_scopes), toset(var.allowed_scopes)))}."
    }

    precondition {
      condition     = length(setsubtract(local.tool_scopes, toset(var.oauth_scopes))) == 0
      error_message = "A tool requires a scope that is not requested (MCP-SCOPE-MISSING)."
    }

    precondition {
      condition     = length(setsubtract(toset(var.oauth_scopes), local.tool_scopes)) == 0
      error_message = "A requested scope is not needed by any tool (MCP-SCOPE-UNUSED). Drop it."
    }

    precondition {
      condition     = var.environment == "dev" || length(trimspace(var.review_ticket)) > 0
      error_message = "staging and prod require a review_ticket."
    }
  }
}

resource "local_file" "manifest" {
  filename        = "${var.output_dir}/${var.environment}/${var.name}.manifest.json"
  content         = local.manifest_json
  file_permission = "0644"

  depends_on = [terraform_data.guard]
}

resource "local_file" "registration" {
  filename        = "${var.output_dir}/${var.environment}/${var.name}.registration.json"
  content         = jsonencode(local.registration)
  file_permission = "0644"

  depends_on = [terraform_data.guard]
}
