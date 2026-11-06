output "network_self_link" {
  description = "Self-link of the dedicated canary VPC."
  value       = google_compute_network.canary.self_link
}

output "subnetwork_self_link" {
  description = "Self-link of the only canary subnet."
  value       = google_compute_subnetwork.canary.self_link
}

output "network_name" {
  description = "Name of the dedicated canary VPC."
  value       = google_compute_network.canary.name
}

output "subnet_name" {
  description = "Name of the only canary subnet."
  value       = google_compute_subnetwork.canary.name
}
