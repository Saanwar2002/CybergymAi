resource "google_compute_network" "canary" {
  name                            = var.network_name
  description                     = "Dedicated isolated network for harmless Cybergym canary runs."
  auto_create_subnetworks         = false
  routing_mode                    = "REGIONAL"
  delete_default_routes_on_create = true
}

resource "google_compute_subnetwork" "canary" {
  name                     = var.subnet_name
  description              = "Only subnet permitted for the Cybergym canary VPC."
  region                   = var.region
  network                  = google_compute_network.canary.id
  ip_cidr_range            = var.ipv4_cidr
  private_ip_google_access = false
  stack_type               = "IPV4_ONLY"
}

resource "google_compute_firewall" "deny_ingress" {
  name      = "${var.network_name}-deny-ingress"
  network   = google_compute_network.canary.id
  direction = "INGRESS"
  priority  = 0

  source_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "all"
  }
}

resource "google_compute_firewall" "deny_egress" {
  name      = "${var.network_name}-deny-egress"
  network   = google_compute_network.canary.id
  direction = "EGRESS"
  priority  = 0

  destination_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "all"
  }
}
