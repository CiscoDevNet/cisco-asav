##################################################
# Variables
##################################################
# Variables with Validation
variable "project_id" {}
variable "resource_name_prefix" {}
variable "region" {}
variable "mgmt_ipv4_cidr" {}
variable "inside_ipv4_cidr" {}
variable "outside_ipv4_cidr" {}

variable "with_diagnostic" {}
variable "diag_ipv4_cidr" {
  default  = ""
  nullable = false
}

variable "cisco_nat_pool" {}
variable "cisco_nat_pool_ipv6" {}
##################################################
# VPC and Subnet Resources

provider "google" {
  project     = var.project_id
  region      = var.region
}

resource "google_compute_network" "mgmt_vpc" {
  name                    = "${var.resource_name_prefix}-mgmt-vpc"
  auto_create_subnetworks = false
  routing_mode            = "GLOBAL"
}

resource "google_compute_subnetwork" "mgmt_subnet" {
  name          = "${var.resource_name_prefix}-mgmt-subnet"
  network       = google_compute_network.mgmt_vpc.self_link
  ip_cidr_range = var.mgmt_ipv4_cidr
  stack_type    = "IPV4_IPV6"
  region        = var.region
  ipv6_access_type = "EXTERNAL"
}

resource "google_compute_network" "inside_vpc" {
  name                    = "${var.resource_name_prefix}-inside-vpc"
  auto_create_subnetworks = false
  routing_mode            = "GLOBAL"
  mtu                     = 8896
}

resource "google_compute_subnetwork" "inside_subnet" {
  name          = "${var.resource_name_prefix}-inside-subnet"
  network       = google_compute_network.inside_vpc.self_link
  ip_cidr_range = var.inside_ipv4_cidr
  region        = var.region
  stack_type    = "IPV4_IPV6"
  ipv6_access_type = "EXTERNAL"
}

resource "google_compute_network" "outside_vpc" {
  name                    = "${var.resource_name_prefix}-outside-vpc"
  auto_create_subnetworks = false
  routing_mode            = "GLOBAL"
  mtu                     = 8896
}

resource "google_compute_subnetwork" "outside_subnet" {
  name          = "${var.resource_name_prefix}-outside-subnet"
  network       = google_compute_network.outside_vpc.self_link
  ip_cidr_range = var.outside_ipv4_cidr
  region        = var.region
  stack_type    = "IPV4_IPV6"
  ipv6_access_type = "EXTERNAL"
}

resource "google_compute_network" "diag_vpc" {
  name                    = "${var.resource_name_prefix}-diag-vpc"
  auto_create_subnetworks = false
  routing_mode            = "GLOBAL"
  count = lower(tostring(var.with_diagnostic)) == "true" ? 1 : 0
}

resource "google_compute_subnetwork" "diag_subnet" {
  name          = "${var.resource_name_prefix}-diag-subnet"
  network       = google_compute_network.diag_vpc[0].self_link
  ip_cidr_range = var.diag_ipv4_cidr
  region        = var.region
  stack_type    = "IPV4_IPV6"
  ipv6_access_type = "EXTERNAL"
  count = lower(tostring(var.with_diagnostic)) == "true" ? 1 : 0
}

resource "google_compute_firewall" "mgmt_firewall" {
  name    = "${var.resource_name_prefix}-mgmt-firewall-rule"
  network = google_compute_network.mgmt_vpc.self_link

  allow {
    protocol = "tcp"
    ports    = ["22", "443", "8305"]
  }
  allow {
    protocol = "icmp"
  }

  source_ranges = concat([var.mgmt_ipv4_cidr], var.cisco_nat_pool)
}

resource "google_compute_firewall" "mgmt_firewall_ipv6" {
  name    = "${var.resource_name_prefix}-mgmt-firewall-ipv6-rule"
  network = google_compute_network.mgmt_vpc.self_link
  allow {
    protocol = "tcp"
    ports    = ["22", "443", "8305"]
  }
  source_ranges = [google_compute_subnetwork.mgmt_subnet.external_ipv6_prefix]
  depends_on = [google_compute_subnetwork.mgmt_subnet]
}

resource "google_compute_firewall" "diag_firewall" {
  count = lower(tostring(var.with_diagnostic)) == "true" ? 1 : 0
  name    = "${var.resource_name_prefix}-diag-firewall-rule"
  network = google_compute_network.diag_vpc[0].self_link
  allow {
    protocol = "tcp"
    ports    = ["22", "443", "8305"]
  }
  allow {
    protocol = "icmp"
  }

  source_ranges = [var.diag_ipv4_cidr]
}

resource "google_compute_firewall" "inside_firewall" {
  name    = "${var.resource_name_prefix}-in-firewall-rule"
  network = google_compute_network.inside_vpc.self_link
  allow {
    protocol = "tcp"
    ports    = ["80", "443", "22"]
  }
  allow {
    protocol = "icmp"
  }
  source_ranges = concat([var.inside_ipv4_cidr], var.cisco_nat_pool)
}

resource "google_compute_firewall" "inside_firewall_ipv6" {
  name    = "${var.resource_name_prefix}-in-firewall-ipv6-rule"
  network = google_compute_network.inside_vpc.self_link
  allow {
    protocol = "tcp"
    ports    = ["80", "443", "22"]
  }
  allow {
    protocol = "all"
  }
  source_ranges = [google_compute_subnetwork.inside_subnet.external_ipv6_prefix]
  depends_on = [google_compute_subnetwork.inside_subnet]
}

resource "google_compute_firewall" "outside_firewall" {
  name    = "${var.resource_name_prefix}-out-firewall-rule"
  network = google_compute_network.outside_vpc.self_link

  allow {
    protocol = "tcp"
    ports    = ["80", "443", "22"]
  }
  allow {
    protocol = "icmp"
  }

  source_ranges = concat([var.outside_ipv4_cidr], var.cisco_nat_pool)
}

resource "google_compute_firewall" "outside_firewall_ipv6" {
  name    = "${var.resource_name_prefix}-out-firewall-ipv6-rule"
  network = google_compute_network.outside_vpc.self_link

  allow {
    protocol = "tcp"
    ports    = ["80", "443", "22"]
  }

  allow {
    protocol = "all"
  }

  source_ranges = [google_compute_subnetwork.outside_subnet.external_ipv6_prefix]

  depends_on = [google_compute_subnetwork.outside_subnet]
}
# Outputs
output "mgmt_vpc_name" {
  description = "Name of management VPC"
  value = google_compute_network.mgmt_vpc.name
}
output "mgmt_subnet_name" {
  description = "Name of management subnet"
  value = google_compute_subnetwork.mgmt_subnet.name
}
output "mgmt_ipv4_gateway" {
  description = "Management subnet ipv4 gateway"
  value = google_compute_subnetwork.mgmt_subnet.gateway_address
}
output "mgmt_ipv6_cidr"{
  description = "Management subnet ipv6 CIDR"
  value = google_compute_subnetwork.mgmt_subnet.external_ipv6_prefix
}
output "mgmt_ipv6_gateway" {
  description = "Management subnet ipv6 gateway"
  value = cidrhost (google_compute_subnetwork.mgmt_subnet.external_ipv6_prefix, 1)
}
output "inside_vpc_name" {
  description = "Name of inside VPC"
  value = google_compute_network.inside_vpc.name
}
output "inside_subnet_name" {
  description = "Name of inside subnet"
  value = google_compute_subnetwork.inside_subnet.name
}
output "inside_ipv4_gateway" {
  description = "Inside subnet ipv4 gateway"
  value = google_compute_subnetwork.inside_subnet.gateway_address
}
output "inside_ipv6_cidr"{
  description = "Inside subnet ipv6 CIDR"
  value = google_compute_subnetwork.inside_subnet.external_ipv6_prefix
}
output "inside_ipv6_gateway" {
  description = "Inside subnet ipv6 gateway"
  value = cidrhost(google_compute_subnetwork.inside_subnet.external_ipv6_prefix, 1)
}
output "outside_vpc_name" {
  description = "Name of outside VPC"
  value = google_compute_network.outside_vpc.name
}
output "outside_subnet_name" {
  description = "Name of outside subnet"
  value = google_compute_subnetwork.outside_subnet.name
}
output "outside_ipv4_gateway" {
  description = "Outside subnet ipv4 gateway"
  value = google_compute_subnetwork.outside_subnet.gateway_address
}
output "outside_ipv6_cidr"{
  description = "Outside subnet ipv6 CIDR"
  value = google_compute_subnetwork.outside_subnet.external_ipv6_prefix
}
output "outside_ipv6_gateway" {
  description = "Outside subnet ipv6 gateway"
  value = cidrhost(google_compute_subnetwork.outside_subnet.external_ipv6_prefix, 1)
}
output "diag_vpc_name" {
  description = "Name of diagnostic VPC"
  value = lower(tostring(var.with_diagnostic)) == "true" ? google_compute_network.diag_vpc[0].name : null
}
output "diag_subnet_name" {
  description = "Name of diagnostic subnet"
  value = lower(tostring(var.with_diagnostic)) == "true" ? google_compute_subnetwork.diag_subnet[0].name : null
}
output "diag_ipv4_gateway" {
  description = "Diagnostic subnet ipv4 gateway"
  value = lower(tostring(var.with_diagnostic)) == "true" ? google_compute_subnetwork.diag_subnet[0].gateway_address : null
}
output "diag_ipv6_cidr"{
  description = "Diagnostic subnet ipv6 CIDR"
  value = lower(tostring(var.with_diagnostic)) == "true" ? google_compute_subnetwork.diag_subnet[0].external_ipv6_prefix : null
}
output "diag_ipv6_gateway" {
  description = "Diagnostic subnet ipv6 gateway"
  value = lower(tostring(var.with_diagnostic)) == "true" ? cidrhost(google_compute_subnetwork.diag_subnet[0].external_ipv6_prefix, 1) : null
}