variable "project_id" {} # GCP Project ID : 
variable "region" {}     # e.g., us-central1, us-east1
variable "zone" {}       # a,b,c,d, any alphabetical character
variable "resource_name_prefix" {
  default = "automation"
}

variable "image" {
  default = "projects/cisco-public/global/images/cisco-asav-9-23-1"
}
variable "machine_type" {
  default = "n1-standard-4"
}

variable "mgmt_vpc_name" {}
variable "mgmt_subnet_name" {}
variable "inside_vpc_name" {}
variable "inside_subnet_name" {}
variable "outside_vpc_name" {}
variable "outside_subnet_name" {}
variable "day0_config" {}
# variable "admin_password" {}
# variable "enable_password" {}

provider "google" {
  project     = var.project_id
  region      = var.region
}

resource "google_compute_instance" "asav_instance" {
  name         = "${var.resource_name_prefix}-asav"
  machine_type = var.machine_type
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = var.image
      type  = "pd-standard"
    }
  }

  network_interface {
    network    = var.mgmt_vpc_name
    subnetwork = var.mgmt_subnet_name
    stack_type = "IPV4_IPV6"
    access_config {
      network_tier = "PREMIUM"
    }
    ipv6_access_config {
      network_tier = "PREMIUM"
    }
  }

  network_interface {
    network    = var.inside_vpc_name
    subnetwork = var.inside_subnet_name
    stack_type = "IPV4_IPV6"
    ipv6_access_config {
      network_tier = "PREMIUM"
    }
  }

  network_interface {
    network    = var.outside_vpc_name
    subnetwork = var.outside_subnet_name
    stack_type = "IPV4_IPV6"
    ipv6_access_config {
      network_tier = "PREMIUM"
    }
  }

  can_ip_forward = true

  metadata_startup_script = var.day0_config

  labels = {
    autostop = "false"
  }

  lifecycle {
    create_before_destroy = true
  }

}

# Outputs
output "asav_ssh_ip" {
  description = "Public IP address of the management interface"
  value = length(google_compute_instance.asav_instance.network_interface[0].access_config) > 0 ? google_compute_instance.asav_instance.network_interface[0].access_config[0].nat_ip : null
}

output "asav_mgmt_ipv6" {
  description = "IPv6 address of the management interface"
  value = google_compute_instance.asav_instance.network_interface[0].ipv6_access_config[0].external_ipv6
}

output "asav_mgmt_ip" {
  description = "Private IP address of management interface"
  value = google_compute_instance.asav_instance.network_interface[0].network_ip
}

output "asav_inside_ip" {
  description = "Private IP address of inside interface"
  value = google_compute_instance.asav_instance.network_interface[1].network_ip
}

output "asav_inside_ipv6" {
  description = "IPv6 address of inside interface"
  value = google_compute_instance.asav_instance.network_interface[1].ipv6_access_config[0].external_ipv6
}

output "asav_outside_ip" {
  description = "Private IP address of outside interface"
  value = google_compute_instance.asav_instance.network_interface[2].network_ip
}

output "asav_outside_ipv6" {
  description = "IPv6 address of outside interface"
  value = google_compute_instance.asav_instance.network_interface[2].ipv6_access_config[0].external_ipv6
}

output "asav_instance_name" {
  description = "Name of the ASAv instance"
  value = google_compute_instance.asav_instance.name
}
