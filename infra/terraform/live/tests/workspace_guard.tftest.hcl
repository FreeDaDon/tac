variables {
  environment     = "dev"
  approved_groups = ["grp-ai-docs-dev"]
}

run "refuses_plan_when_workspace_differs_from_environment" {
  command = plan

  expect_failures = [terraform_data.workspace_guard]
}
