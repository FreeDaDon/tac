# One root, three environments. Each environment is a Terraform workspace with its own state file under
# state/<env>/, and the workspace guard below refuses a plan whose tfvars do not match the selected workspace.
terraform {
  required_version = ">= 1.6"

  backend "local" {
    workspace_dir = "state"
  }
}

variable "environment" {
  type = string
}

variable "review_ticket" {
  type    = string
  default = ""
}

variable "approved_groups" {
  type = list(string)
}

resource "terraform_data" "workspace_guard" {
  input = var.environment

  lifecycle {
    precondition {
      condition     = terraform.workspace == var.environment
      error_message = "Workspace \"${terraform.workspace}\" does not match environment \"${var.environment}\". Run: terraform workspace select -or-create ${var.environment}"
    }
  }
}

module "docs_search" {
  source = "../modules/mcp-connector"

  name                = "docs-search"
  connector_version   = "1.4.2"
  environment         = var.environment
  server_url          = "https://docs-mcp.corp.example.com/mcp"
  publisher           = "platform-team"
  repository          = "https://git.corp.example.com/platform/docs-mcp"
  oauth_scopes        = ["docs.read"]
  allowed_scopes      = ["docs.read", "docs.list"]
  approved_groups     = var.approved_groups
  data_classification = "internal"
  review_ticket       = var.review_ticket
  output_dir          = "${path.root}/rendered"

  tools = [{
    name            = "search_docs"
    description     = "Search the internal documentation index."
    read_only       = true
    open_world      = false
    required_scopes = ["docs.read"]
    input_schema = jsonencode({
      type                 = "object"
      additionalProperties = false
      properties           = { query = { type = "string", maxLength = 200 } }
    })
  }]
}

output "manifest_path" {
  value = module.docs_search.manifest_path
}
