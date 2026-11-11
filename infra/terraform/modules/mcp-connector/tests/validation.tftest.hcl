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

  assert {
    condition     = output.manifest_sha256 == sha256(local_file.manifest.content)
    error_message = "manifest_sha256 output must be the sha256 of the rendered manifest content."
  }

  assert {
    condition     = jsondecode(local_file.registration.content).manifest_sha256 == sha256(local_file.manifest.content)
    error_message = "The registration record must carry the sha256 of the rendered manifest content."
  }

  assert {
    condition     = jsondecode(local_file.manifest.content).tools[0].annotations.openWorldHint == true
    error_message = "openWorldHint must default to true when a tool does not declare open_world."
  }

  assert {
    condition     = jsondecode(local_file.manifest.content).tools[0].inputSchema.additionalProperties == false
    error_message = "The default input schema must render with additionalProperties = false."
  }
}

run "renders_declared_closed_world_tool" {
  command = plan

  variables {
    tools = [{
      name            = "search_docs"
      description     = "Search the internal documentation index."
      read_only       = true
      open_world      = false
      required_scopes = ["docs.read"]
      input_schema    = "{\"type\":\"object\",\"additionalProperties\":false,\"properties\":{\"query\":{\"type\":\"string\"}}}"
    }]
  }

  assert {
    condition     = jsondecode(local_file.manifest.content).tools[0].annotations.openWorldHint == false
    error_message = "A tool that declares open_world = false must render openWorldHint = false."
  }

  assert {
    condition     = jsondecode(local_file.manifest.content).tools[0].inputSchema.properties.query.type == "string"
    error_message = "input_schema must render as a decoded JSON object, not a string."
  }
}

run "accepts_hostname_with_port_and_path" {
  command = plan

  variables {
    server_url = "https://docs-mcp.corp.example.com:8443/v1/mcp"
  }
}

run "staging_accepts_real_ticket" {
  command = plan

  variables {
    environment   = "staging"
    review_ticket = "AICR-1234"
  }
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

run "rejects_url_localhost_uppercase" {
  command = plan

  variables {
    server_url = "https://LOCALHOST/"
  }

  expect_failures = [var.server_url]
}

run "rejects_url_localhost_subdomain" {
  command = plan

  variables {
    server_url = "https://evil.localhost/mcp"
  }

  expect_failures = [var.server_url]
}

run "rejects_url_localhost_localdomain" {
  command = plan

  variables {
    server_url = "https://localhost.localdomain/mcp"
  }

  expect_failures = [var.server_url]
}

run "rejects_url_userinfo_loopback" {
  command = plan

  variables {
    server_url = "https://user@127.0.0.1/"
  }

  expect_failures = [var.server_url]
}

run "rejects_url_userinfo_before_real_host" {
  command = plan

  variables {
    server_url = "https://docs-mcp.corp.example.com@127.0.0.1/mcp"
  }

  expect_failures = [var.server_url]
}

run "rejects_url_ipv4_mapped_ipv6" {
  command = plan

  variables {
    server_url = "https://[::ffff:127.0.0.1]/"
  }

  expect_failures = [var.server_url]
}

run "rejects_url_ipv6_loopback" {
  command = plan

  variables {
    server_url = "https://[::1]/mcp"
  }

  expect_failures = [var.server_url]
}

run "rejects_url_decimal_ip" {
  command = plan

  variables {
    server_url = "https://2130706433/"
  }

  expect_failures = [var.server_url]
}

run "rejects_url_hex_ip" {
  command = plan

  variables {
    server_url = "https://0x7f000001/"
  }

  expect_failures = [var.server_url]
}

run "rejects_url_octal_ip" {
  command = plan

  variables {
    server_url = "https://0177.0.0.1/"
  }

  expect_failures = [var.server_url]
}

run "rejects_url_loopback_127_8" {
  command = plan

  variables {
    server_url = "https://127.1.2.3/mcp"
  }

  expect_failures = [var.server_url]
}

run "rejects_url_link_local_metadata_ip" {
  command = plan

  variables {
    server_url = "https://169.254.169.254/"
  }

  expect_failures = [var.server_url]
}

run "rejects_url_metadata_hostname" {
  command = plan

  variables {
    server_url = "https://metadata.google.internal/computeMetadata/v1/"
  }

  expect_failures = [var.server_url]
}

run "rejects_url_rfc1918_10" {
  command = plan

  variables {
    server_url = "https://10.0.0.5/mcp"
  }

  expect_failures = [var.server_url]
}

run "rejects_url_rfc1918_172_16" {
  command = plan

  variables {
    server_url = "https://172.16.0.1/mcp"
  }

  expect_failures = [var.server_url]
}

run "rejects_url_rfc1918_192_168" {
  command = plan

  variables {
    server_url = "https://192.168.1.10/mcp"
  }

  expect_failures = [var.server_url]
}

run "rejects_url_unspecified_ip" {
  command = plan

  variables {
    server_url = "https://0.0.0.0/mcp"
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

run "rejects_trailing_wildcard_scope" {
  command = plan

  variables {
    oauth_scopes   = ["docs*"]
    allowed_scopes = ["docs*"]
    tools          = [{ name = "t", description = "d", read_only = true, required_scopes = ["docs*"] }]
  }

  expect_failures = [var.oauth_scopes]
}

run "rejects_embedded_wildcard_scope" {
  command = plan

  variables {
    oauth_scopes   = ["docs.*.read"]
    allowed_scopes = ["docs.*.read"]
    tools          = [{ name = "t", description = "d", read_only = true, required_scopes = ["docs.*.read"] }]
  }

  expect_failures = [var.oauth_scopes]
}

run "rejects_cloud_platform_scope" {
  command = plan

  variables {
    oauth_scopes   = ["https://www.googleapis.com/auth/cloud-platform"]
    allowed_scopes = ["https://www.googleapis.com/auth/cloud-platform"]
    tools          = [{ name = "t", description = "d", read_only = true, required_scopes = ["https://www.googleapis.com/auth/cloud-platform"] }]
  }

  expect_failures = [var.oauth_scopes]
}

run "rejects_graph_default_scope" {
  command = plan

  variables {
    oauth_scopes   = ["https://graph.microsoft.com/.default"]
    allowed_scopes = ["https://graph.microsoft.com/.default"]
    tools          = [{ name = "t", description = "d", read_only = true, required_scopes = ["https://graph.microsoft.com/.default"] }]
  }

  expect_failures = [var.oauth_scopes]
}

run "rejects_full_gmail_scope" {
  command = plan

  variables {
    oauth_scopes   = ["https://mail.google.com/"]
    allowed_scopes = ["https://mail.google.com/"]
    tools          = [{ name = "t", description = "d", read_only = true, required_scopes = ["https://mail.google.com/"] }]
  }

  expect_failures = [var.oauth_scopes]
}

run "rejects_full_drive_scope" {
  command = plan

  variables {
    oauth_scopes   = ["https://www.googleapis.com/auth/drive"]
    allowed_scopes = ["https://www.googleapis.com/auth/drive"]
    tools          = [{ name = "t", description = "d", read_only = true, required_scopes = ["https://www.googleapis.com/auth/drive"] }]
  }

  expect_failures = [var.oauth_scopes]
}

run "rejects_dot_all_scope" {
  command = plan

  variables {
    oauth_scopes   = ["Files.ReadWrite.All"]
    allowed_scopes = ["Files.ReadWrite.All"]
    tools          = [{ name = "t", description = "d", read_only = true, required_scopes = ["Files.ReadWrite.All"] }]
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

run "rejects_empty_group_list" {
  command = plan

  variables {
    approved_groups = []
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

run "rejects_scope_missing" {
  command = plan

  variables {
    tools = [{ name = "t", description = "d", read_only = true, required_scopes = ["docs.read", "docs.list"] }]
  }

  expect_failures = [terraform_data.guard]
}

run "rejects_scope_unused" {
  command = plan

  variables {
    oauth_scopes = ["docs.read", "docs.list"]
  }

  expect_failures = [terraform_data.guard]
}

run "rejects_zero_tools" {
  command = plan

  variables {
    tools = []
  }

  expect_failures = [var.tools]
}

run "rejects_26_tools" {
  command = plan

  variables {
    tools = [
      { name = "t01", description = "d", read_only = true, required_scopes = ["docs.read"] },
      { name = "t02", description = "d", read_only = true, required_scopes = ["docs.read"] },
      { name = "t03", description = "d", read_only = true, required_scopes = ["docs.read"] },
      { name = "t04", description = "d", read_only = true, required_scopes = ["docs.read"] },
      { name = "t05", description = "d", read_only = true, required_scopes = ["docs.read"] },
      { name = "t06", description = "d", read_only = true, required_scopes = ["docs.read"] },
      { name = "t07", description = "d", read_only = true, required_scopes = ["docs.read"] },
      { name = "t08", description = "d", read_only = true, required_scopes = ["docs.read"] },
      { name = "t09", description = "d", read_only = true, required_scopes = ["docs.read"] },
      { name = "t10", description = "d", read_only = true, required_scopes = ["docs.read"] },
      { name = "t11", description = "d", read_only = true, required_scopes = ["docs.read"] },
      { name = "t12", description = "d", read_only = true, required_scopes = ["docs.read"] },
      { name = "t13", description = "d", read_only = true, required_scopes = ["docs.read"] },
      { name = "t14", description = "d", read_only = true, required_scopes = ["docs.read"] },
      { name = "t15", description = "d", read_only = true, required_scopes = ["docs.read"] },
      { name = "t16", description = "d", read_only = true, required_scopes = ["docs.read"] },
      { name = "t17", description = "d", read_only = true, required_scopes = ["docs.read"] },
      { name = "t18", description = "d", read_only = true, required_scopes = ["docs.read"] },
      { name = "t19", description = "d", read_only = true, required_scopes = ["docs.read"] },
      { name = "t20", description = "d", read_only = true, required_scopes = ["docs.read"] },
      { name = "t21", description = "d", read_only = true, required_scopes = ["docs.read"] },
      { name = "t22", description = "d", read_only = true, required_scopes = ["docs.read"] },
      { name = "t23", description = "d", read_only = true, required_scopes = ["docs.read"] },
      { name = "t24", description = "d", read_only = true, required_scopes = ["docs.read"] },
      { name = "t25", description = "d", read_only = true, required_scopes = ["docs.read"] },
      { name = "t26", description = "d", read_only = true, required_scopes = ["docs.read"] },
    ]
  }

  expect_failures = [var.tools]
}

run "rejects_duplicate_tool_names" {
  command = plan

  variables {
    tools = [
      { name = "search_docs", description = "a", read_only = true, required_scopes = ["docs.read"] },
      { name = "search_docs", description = "b", read_only = true, required_scopes = ["docs.read"] },
    ]
  }

  expect_failures = [var.tools]
}

run "rejects_schema_without_additional_properties" {
  command = plan

  variables {
    tools = [{ name = "t", description = "d", read_only = true, required_scopes = ["docs.read"], input_schema = "{\"type\":\"object\",\"properties\":{}}" }]
  }

  expect_failures = [var.tools]
}

run "rejects_schema_with_additional_properties_true" {
  command = plan

  variables {
    tools = [{ name = "t", description = "d", read_only = true, required_scopes = ["docs.read"], input_schema = "{\"type\":\"object\",\"additionalProperties\":true}" }]
  }

  expect_failures = [var.tools]
}

run "rejects_schema_not_json" {
  command = plan

  variables {
    tools = [{ name = "t", description = "d", read_only = true, required_scopes = ["docs.read"], input_schema = "not json" }]
  }

  expect_failures = [var.tools]
}

run "rejects_plaintext_repository" {
  command = plan

  variables {
    repository = "http://git.corp.example.com/platform/docs-mcp"
  }

  expect_failures = [var.repository]
}

run "rejects_repository_with_credentials" {
  command = plan

  variables {
    repository = "https://token@git.corp.example.com/platform/docs-mcp"
  }

  expect_failures = [var.repository]
}

run "prod_requires_ticket" {
  command = plan

  variables {
    environment = "prod"
  }

  expect_failures = [terraform_data.guard]
}

run "staging_rejects_placeholder_ticket" {
  command = plan

  variables {
    environment   = "staging"
    review_ticket = "AICR-0000"
  }

  expect_failures = [var.review_ticket]
}

run "staging_rejects_tfvars_placeholder" {
  command = plan

  variables {
    environment   = "staging"
    review_ticket = "SET-REAL-AICR-TICKET"
  }

  expect_failures = [var.review_ticket]
}

run "prod_rejects_placeholder_ticket" {
  command = plan

  variables {
    environment   = "prod"
    review_ticket = "AICR-0000"
  }

  expect_failures = [var.review_ticket]
}

run "prod_rejects_tfvars_placeholder" {
  command = plan

  variables {
    environment   = "prod"
    review_ticket = "SET-REAL-AICR-TICKET"
  }

  expect_failures = [var.review_ticket]
}
