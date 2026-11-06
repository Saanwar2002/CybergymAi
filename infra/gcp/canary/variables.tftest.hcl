mock_provider "google" {}

run "accepts_private_canonical_cidr" {
  command = plan

  variables {
    project_id = "cybergym-canary"
    ipv4_cidr  = "10.240.0.0/24"
  }
}

run "rejects_public_cidr" {
  command = plan

  variables {
    project_id = "cybergym-canary"
    ipv4_cidr  = "8.8.8.0/24"
  }

  expect_failures = [var.ipv4_cidr]
}

run "rejects_subnet_larger_than_policy" {
  command = plan

  variables {
    project_id = "cybergym-canary"
    ipv4_cidr  = "10.240.0.0/23"
  }

  expect_failures = [var.ipv4_cidr]
}

run "rejects_noncanonical_network_address" {
  command = plan

  variables {
    project_id = "cybergym-canary"
    ipv4_cidr  = "10.240.0.1/24"
  }

  expect_failures = [var.ipv4_cidr]
}
