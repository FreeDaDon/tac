variables {
  name                = "docs-search"
  connector_version   = "1.4.2"
  environment         = "dev"
  server_url          = "https://docs-mcp.corp.example.com/mcp"
  publisher           = "platform-team"
  repository          = "https://git.corp.example.com/platform/docs-mcp"
  oauth_scopes        = ["docs.read"]
  allowed_scopes      = ["docs.read", "docs.list"]
  approved_groups     = ["grp-ai-docs-users"]
  data_classification = "internal"
  tools = [{
    name            = "search_docs"
    description     = "Search the internal documentation index."
    read_only       = true
    required_scopes = ["docs.read"]
  }]
}

run "clean_connector_plans" {
  command = plan
}

run "rejects_latest_version" {
  command = plan
  variables {
    connector_version = "latest"
  }
  expect_failures = [var.connector_version]
}

run "rejects_plaintext_url" {
  command = plan
  variables {
    server_url = "http://docs-mcp.corp.example.com/mcp"
  }
  expect_failures = [var.server_url]
}

run "rejects_admin_scope" {
  command = plan
  variables {
    oauth_scopes   = ["docs.admin"]
    allowed_scopes = ["docs.admin"]
    tools          = [{ name = "t", description = "d", read_only = true, required_scopes = ["docs.admin"] }]
  }
  expect_failures = [var.oauth_scopes]
}

run "rejects_broad_audience" {
  command = plan
  variables {
    approved_groups = ["all employees"]
  }
  expect_failures = [var.approved_groups]
}

run "rejects_scope_outside_allowlist" {
  command = plan
  variables {
    allowed_scopes = ["docs.list"]
  }
  expect_failures = [terraform_data.guard]
}

run "prod_requires_ticket" {
  command = plan
  variables {
    environment = "prod"
  }
  expect_failures = [terraform_data.guard]
}
