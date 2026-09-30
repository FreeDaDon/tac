# One root, three environments: select with -var-file=envs/<env>.tfvars and keep a separate state per environment.
terraform {
  required_version = ">= 1.6"
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
    required_scopes = ["docs.read"]
    input_schema = {
      type                 = "object"
      additionalProperties = false
      properties           = { query = { type = "string", maxLength = 200 } }
    }
  }]
}

output "manifest_path" {
  value = module.docs_search.manifest_path
}
