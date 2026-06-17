provider "google" {
  project     = var.project_id
  region      = var.region
}

# Variables
variable "project_id" {}
variable "resource_name_prefix" {}
variable "region" {}
variable "mgmt_ip_cidr_range" {}
variable "vpc_connector_ip_cidr_range" {}
variable "inside_ip_cidr_range" {}
variable "outside_ip_cidr_range" {}
variable "ccl_ip_cidr_range" {}

# VPC and Subnet Resources
resource "google_compute_network" "mgmt_vpc" {
  name                    = "${var.resource_name_prefix}-asav-mgmt-vpc"
  auto_create_subnetworks = false
  routing_mode            = "GLOBAL"
}

resource "google_compute_subnetwork" "mgmt_subnet" {
  name          = "${var.resource_name_prefix}-asav-mgmt-subnet"
  network       = google_compute_network.mgmt_vpc.self_link
  ip_cidr_range = var.mgmt_ip_cidr_range
  region        = var.region
}

resource "google_compute_subnetwork" "mgmt_vpc_connector_subnet" {
  name          = "${var.resource_name_prefix}-vpc-connector-subnet28"
  network       = google_compute_network.mgmt_vpc.self_link
  ip_cidr_range = var.vpc_connector_ip_cidr_range
  region        = var.region
}

resource "google_compute_network" "inside_vpc" {
  name                    = "${var.resource_name_prefix}-asav-inside-vpc"
  auto_create_subnetworks = false
  routing_mode            = "GLOBAL"
  mtu = 8896
}

resource "google_compute_subnetwork" "inside_subnet" {
  name          = "${var.resource_name_prefix}-asav-inside-subnet"
  network       = google_compute_network.inside_vpc.self_link
  ip_cidr_range = var.inside_ip_cidr_range
  region        = var.region
}

resource "google_compute_network" "outside_vpc" {
  name                    = "${var.resource_name_prefix}-asav-outside-vpc"
  auto_create_subnetworks = false
  routing_mode            = "GLOBAL"
  mtu = 8896
}

resource "google_compute_subnetwork" "outside_subnet" {
  name          = "${var.resource_name_prefix}-asav-outside-subnet"
  network       = google_compute_network.outside_vpc.self_link
  ip_cidr_range = var.outside_ip_cidr_range
  region        = var.region
}

resource "google_compute_network" "ccl_vpc" {
  name                    = "${var.resource_name_prefix}-asav-ccl-vpc"
  auto_create_subnetworks = false
  routing_mode            = "GLOBAL"
  mtu = 8896
}

resource "google_compute_subnetwork" "ccl_subnet" {
  name          = "${var.resource_name_prefix}-asav-ccl-subnet"
  network       = google_compute_network.ccl_vpc.self_link
  ip_cidr_range = var.ccl_ip_cidr_range
  region        = var.region
}


resource "google_compute_firewall" "mgmt_firewall" {
  name    = "${var.resource_name_prefix}-asav-mgmt-firewall-rule"
  network = google_compute_network.mgmt_vpc.self_link

  allow {
    protocol = "tcp"
    ports    = ["22", "443", "8305"]
  }
  allow {
    protocol = "icmp"
  }

  source_ranges = [var.mgmt_ip_cidr_range]
}

resource "google_compute_firewall" "vpc_connector_ingress" {
  name    = "${var.resource_name_prefix}-vpc-connector-ingress"
  network = google_compute_network.mgmt_vpc.self_link

  allow {
    protocol = "all"
  }

  source_ranges = [var.vpc_connector_ip_cidr_range]
}

resource "google_compute_firewall" "inside_firewall" {
  name    = "${var.resource_name_prefix}-asav-in-firewall-rule"
  network = google_compute_network.inside_vpc.self_link

  allow {
    protocol = "tcp"
    ports    = ["80", "443", "22"]
  }

  allow {
    protocol = "icmp"
  }

  source_ranges = [var.inside_ip_cidr_range]
}

resource "google_compute_firewall" "outside_firewall" {
  name    = "${var.resource_name_prefix}-asav-out-firewall-rule"
  network = google_compute_network.outside_vpc.self_link

  allow {
    protocol = "tcp"
    ports    = ["80", "443", "22"]
  }
  allow {
    protocol = "icmp"
  }

  source_ranges = [var.outside_ip_cidr_range]
}

resource "google_compute_firewall" "ccl_firewall" {
  name    = "${var.resource_name_prefix}-asav-ccl-firewall-rule"
  network = google_compute_network.ccl_vpc.self_link

  allow {
    protocol = "all"
  }

  source_ranges = [var.ccl_ip_cidr_range]
}

resource "google_compute_firewall" "inside_hc_firewall" {
  name    = "${var.resource_name_prefix}-asav-in-hc-firewall-rule"
  network = google_compute_network.inside_vpc.self_link

  allow {
    protocol = "tcp"
  }
  source_ranges = ["130.211.0.0/22", "35.191.0.0/16", "209.85.152.0/22", "209.85.204.0/22"]
}

resource "google_compute_firewall" "outside_hc_firewall" {
  name    = "${var.resource_name_prefix}-asav-out-hc-firewall-rule"
  network = google_compute_network.outside_vpc.self_link

  allow {
    protocol = "tcp"
  }
  source_ranges = ["130.211.0.0/22", "35.191.0.0/16", "209.85.152.0/22", "209.85.204.0/22"]
}

resource "google_vpc_access_connector" "connector" {
  name          = "${var.resource_name_prefix}-connector"
  subnet {
    name = google_compute_subnetwork.mgmt_vpc_connector_subnet.name
  }
  max_instances = 10
  min_instances = 2
}

# VPC Outputs
output "mgmt_vpc_name" {
  value = google_compute_network.mgmt_vpc.name
}

output "inside_vpc_name" {
  value = google_compute_network.inside_vpc.name
}

output "outside_vpc_name" {
  value = google_compute_network.outside_vpc.name
}

output "ccl_vpc_name" {
  value = google_compute_network.ccl_vpc.name
}

# Subnet Names
output "mgmt_subnet_name" {
  value = google_compute_subnetwork.mgmt_subnet.name
}
output "inside_subnet_name" {
  value = google_compute_subnetwork.inside_subnet.name
}

output "outside_subnet_name" {
  value = google_compute_subnetwork.outside_subnet.name
}

output "ccl_subnet_name" {
  value = google_compute_subnetwork.ccl_subnet.name
}

##VPC Connector Outputs
output "vpc_connector_name" {
  value = google_vpc_access_connector.connector.name
}


##Firewall Rule Outputs
output "mgmt_firewall_rule_name" {
  description = "Name of the management firewall rule"
  value       = google_compute_firewall.mgmt_firewall.name
}

output "inside_firewall_rule_name" {
  description = "Name of the inside firewall rule"
  value       = google_compute_firewall.inside_firewall.name
}

output "outside_firewall_rule_name" {
  description = "Name of the outside firewall rule"
  value       = google_compute_firewall.outside_firewall.name
}

output "ccl_firewall_rule_name" {
  description = "Name of the ccl firewall rule"
  value       = google_compute_firewall.ccl_firewall.name
}

output "inside_hc_firewall_rule_name" {
  description = "Name of the inside health check firewall rule"
  value       = google_compute_firewall.inside_hc_firewall.name
}

output "outside_hc_firewall_rule_name" {
  description = "Name of the outside health check firewall rule"
  value       = google_compute_firewall.outside_hc_firewall.name
}
