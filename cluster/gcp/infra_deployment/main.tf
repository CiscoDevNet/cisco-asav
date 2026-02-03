provider "google" {
  project = var.project_id
  region  = var.region
}


## Variables

variable "project_id" {
  description = "The GCP project ID where resources will be deployed."
  type        = string
  validation {
    condition     = length(var.project_id) > 0
    error_message = "The project_id must not be empty."
  }
}

variable "resource_name_prefix" {
  description = "Prefix for naming resources to ensure uniqueness."
  type        = string
  validation {
    condition     = length(var.resource_name_prefix) > 0 && length(var.resource_name_prefix) <= 15
    error_message = "The resource_name_prefix must not be empty."
  }
}

variable "region" {
  description = "The region where the resources will be deployed."
  type        = string
  validation {
    condition     = length(var.region) > 0
    error_message = "The region must not be empty."
  }
}

variable "mgmt_vpc_routing_mode" {
  description = "The routing mode for the management VPC."
  type        = string
  default     = "REGIONAL"
  validation {
    condition     = var.mgmt_vpc_routing_mode == "REGIONAL" || var.mgmt_vpc_routing_mode == "GLOBAL"
    error_message = "The mgmt_vpc_routing_mode must be either 'REGIONAL' or 'GLOBAL'."
  }
}

variable "mgmt_ip_cidr_range" {
  description = "CIDR range for the management VPC."
  type        = string
}

variable "vpc_connector_ip_cidr_range" {
  description = "CIDR range for the VPC connector."
  type        = string
}

variable "inside_vpc_routing_mode" {
  description = "The routing mode for the inside VPC."
  type        = string
  default     = "REGIONAL"
  validation {
    condition     = var.inside_vpc_routing_mode == "REGIONAL" || var.inside_vpc_routing_mode == "GLOBAL"
    error_message = "The inside_vpc_routing_mode must be either 'REGIONAL' or 'GLOBAL'."
  }
}

variable "inside_ip_cidr_range" {
  description = "CIDR range for the inside VPC."
  type        = string
}

variable "outside_vpc_routing_mode" {
  description = "The routing mode for the outside VPC."
  type        = string
  default     = "REGIONAL"
  validation {
    condition     = var.outside_vpc_routing_mode == "REGIONAL" || var.outside_vpc_routing_mode == "GLOBAL"
    error_message = "The outside_vpc_routing_mode must be either 'REGIONAL' or 'GLOBAL'."
  }
}

variable "outside_ip_cidr_range" {
  description = "CIDR range for the outside VPC."
  type        = string
}


variable "ccl_vpc_routing_mode" {
  description = "The routing mode for the CCL VPC."
  type        = string
  default     = "REGIONAL"
  validation {
    condition     = var.ccl_vpc_routing_mode == "REGIONAL" || var.ccl_vpc_routing_mode == "GLOBAL"
    error_message = "The ccl_vpc_routing_mode must be either 'REGIONAL' or 'GLOBAL'."
  }
  
}

variable "ccl_ip_cidr_range" {
  description = "CIDR range for the CCL VPC."
  type        = string
}

##################################################
# VPC and Subnet Resources

resource "google_compute_network" "mgmt_vpc" {
  name                    = "${var.resource_name_prefix}-mgmt-vpc"
  auto_create_subnetworks = false
  routing_mode            = var.mgmt_vpc_routing_mode
}

resource "google_compute_subnetwork" "mgmt_subnet" {
  name          = "${var.resource_name_prefix}-mgmt-subnet"
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
  name                    = "${var.resource_name_prefix}-inside-vpc"
  auto_create_subnetworks = false
  routing_mode            = var.inside_vpc_routing_mode
  mtu                     = 8896 
}

resource "google_compute_subnetwork" "inside_subnet" {
  name          = "${var.resource_name_prefix}-inside-subnet"
  network       = google_compute_network.inside_vpc.self_link
  ip_cidr_range = var.inside_ip_cidr_range
  region        = var.region
}

resource "google_compute_network" "outside_vpc" {
  name                    = "${var.resource_name_prefix}-outside-vpc"
  auto_create_subnetworks = false
  routing_mode            = var.outside_vpc_routing_mode
  mtu                     = 8896 
}

resource "google_compute_subnetwork" "outside_subnet" {
  name          = "${var.resource_name_prefix}-outside-subnet"
  network       = google_compute_network.outside_vpc.self_link
  ip_cidr_range = var.outside_ip_cidr_range
  region        = var.region
}

resource "google_compute_network" "ccl_vpc" {
  name                    = "${var.resource_name_prefix}-ccl-vpc"
  auto_create_subnetworks = false
  routing_mode            = var.ccl_vpc_routing_mode
  mtu                     = 8896 
}

resource "google_compute_subnetwork" "ccl_subnet" {
  name          = "${var.resource_name_prefix}-ccl-subnet"
  network       = google_compute_network.ccl_vpc.self_link
  ip_cidr_range = var.ccl_ip_cidr_range
  region        = var.region
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
  name    = "${var.resource_name_prefix}-in-firewall-rule"
  network = google_compute_network.inside_vpc.self_link

  allow {
    protocol = "tcp"
    ports    = ["80", "443", "22"]
  }

  allow {
    protocol = "icmp"
  }

  source_ranges = [var.inside_ip_cidr_range, "130.211.0.0/22", "35.191.0.0/16", "209.85.152.0/22", "209.85.204.0/22"]
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

  source_ranges = [var.outside_ip_cidr_range, "130.211.0.0/22", "35.191.0.0/16", "209.85.152.0/22", "209.85.204.0/22"]
}

resource "google_compute_firewall" "ccl_firewall" {
  name        = "${var.resource_name_prefix}-ccl-firewall-rule"
  network     = google_compute_network.ccl_vpc.self_link
  
  allow {
    protocol = "all"
  }
  
  source_ranges = [var.ccl_ip_cidr_range]
}

resource "google_vpc_access_connector" "connector" {
  name = "${var.resource_name_prefix}-connector"
  subnet {
    name = google_compute_subnetwork.mgmt_vpc_connector_subnet.name
  }
  max_instances = 10
  min_instances = 2
}
