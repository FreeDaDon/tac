output "manifest_path" {
  description = "Rendered manifest. Feed it to the scanner before any registration step."
  value       = local_file.manifest.filename
}

output "registration_path" {
  description = "Rendered registration record (environment, classification, ticket, manifest hash, audience)."
  value       = local_file.registration.filename
}

output "manifest_sha256" {
  description = "Hash of the reviewed manifest. Registration must match it."
  value       = local.registration.manifest_sha256
}
