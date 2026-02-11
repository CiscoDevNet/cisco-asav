variable "project_id" {}
variable "service_account_mail_id" {}
variable "region" {}
variable "zone1" {}
variable "zone2" {}
variable "zone3" {}

variable "resource_name_prefix" {}

variable "machine_type" {}
variable "source_image_url" {}

variable "outside_vpc_name" {}
variable "inside_vpc_name" {}
variable "mgmt_vpc_name" {}
variable "ccl_vpc_name" {}

variable "outside_subnet_name" {}
variable "inside_subnet_name" {}
variable "mgmt_subnet_name" {}
variable "ccl_subnet_name" {}

variable "mgmt_firewall_rule_name" {}
variable "outside_firewall_rule_name" {}
variable "inside_firewall_rule_name" {}
variable "ccl_firewall_rule_name" {}

variable "public_key" {}
variable "assign_public_ip_to_mgmt" {}
variable "ccl_subnet_firstIp" {}
variable "ccl_subnet_lastIp" {}
variable "cluster_grp_name" {}

variable "auto_scaling" {}
variable "max_asa_count" {}
variable "min_asa_count" {}
variable "cpu_utilization_target" {}
variable "license_throughput" {}
variable "license_token" {}

variable "ilb_backend_protocol" {}
variable "ilb_frontend_protocol" {}
variable "ilb_health_check_port" {}

variable "ilb_check_interval_sec" {}
variable "ilb_timeout_sec" {}
variable "ilb_unhealthy_threshold" {}

data "google_compute_subnetwork" "inside_subnet" {
  name = var.inside_subnet_name
}

data "google_compute_subnetwork" "mgmt_subnet" {
  name = var.mgmt_subnet_name
}

# Instance Template
resource "google_compute_instance_template" "asav_instance_template" {
  name           = "${var.resource_name_prefix}-asav-instance-template"
  description    = "This template is used to create ASAv Cluster instances."
  machine_type   = var.machine_type
  can_ip_forward = true

  tags = concat([
    var.mgmt_firewall_rule_name,
    var.outside_firewall_rule_name,
    var.inside_firewall_rule_name,
    var.ccl_firewall_rule_name
  ])

  disk {
    boot         = true
    auto_delete  = true
    source_image = var.source_image_url
    disk_type    = "pd-standard"
  }
  network_interface {
    network    = "projects/${var.project_id}/global/networks/${var.outside_vpc_name}"
    subnetwork = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.outside_subnet_name}"
  }
  network_interface {
    network = "projects/${var.project_id}/global/networks/${var.mgmt_vpc_name}"
    dynamic "access_config" {
      for_each = var.assign_public_ip_to_mgmt ? [1] : []
      content {
        // This will automatically assign a public IP to the instance
      }
    }
    subnetwork = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.mgmt_subnet_name}"
  }
  network_interface {
    network    = "projects/${var.project_id}/global/networks/${var.inside_vpc_name}"
    subnetwork = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.inside_subnet_name}"
  }
  network_interface {
    network    = "projects/${var.project_id}/global/networks/${var.ccl_vpc_name}"
    subnetwork = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.ccl_subnet_name}"
  }

  metadata = {
    startup-script = <<-EOF
                !
                jumbo-frame reservation
                !
                cluster interface-mode individual force
                !
                interface Management0/0
                  management-only
                  nameif management
                  security-level 100
                  ip address dhcp
                !
                interface GigabitEthernet0/0
                  nameif outside
                  security-level 0
                  ip address dhcp setroute
                  no shutdown
                !
                interface GigabitEthernet0/1
                  nameif inside
                  security-level 100
                  ip address dhcp
                  no shutdown
                !
                interface GigabitEthernet0/2
                  nve-only cluster
                  nameif ccl_link
                  security-level 0
                  ip address dhcp
                !
                interface vni1
                  description Clustering Interface
                  segment-id 1
                  vtep-nve 1
                !
                management-interface swap
                !
                object network ccl_link
                 range ${var.ccl_subnet_firstIp} ${var.ccl_subnet_lastIp}
                object-group network cluster_group
                 network-object object ccl_link
                !
                nve 1
                 encapsulation vxlan
                 source-interface ccl_link
                 peer-group cluster_group
                !
                same-security-traffic permit inter-interface
                same-security-traffic permit intra-interface
                !
                mtu management 1500
                mtu inside 1400
                mtu outside 1400
                mtu ccl_link 1554
                !
                route management 0.0.0.0 0.0.0.0 ${data.google_compute_subnetwork.mgmt_subnet.gateway_address} 2
                route inside 0.0.0.0 0.0.0.0 ${data.google_compute_subnetwork.inside_subnet.gateway_address} 3
                !
                crypto key generate rsa modulus 2048
                ssh 0.0.0.0 0.0.0.0 management
                ssh version 2
                ssh timeout 60
                aaa authentication ssh console LOCAL
                username admin password AsAv_ClU3TeR44 privilege 15
                username admin attributes
                service-type admin
                !
                dns domain-lookup management
                DNS server-group DefaultDNS
                name-server 8.8.8.8 management
                !
                access-list all extended permit ip any any
                access-list out standard permit any4
                access-group all global
                ! Objects
                object-group network GCP-HC
                network-object 35.191.0.0 255.255.0.0
                network-object 130.211.0.0 255.255.252.0
                network-object 209.85.152.0 255.255.252.0
                network-object 209.85.204.0 255.255.252.0
                object network METADATA
                host 169.254.169.254
                object network ILB-INSIDE
                host ${google_compute_address.ilb_ip_inside.address}
                object network ILB-OUTSIDE
                host ${google_compute_address.ilb_ip_outside.address}
                ! Nat Rules
                nat (inside,outside) source dynamic GCP-HC ILB-INSIDE destination static ILB-INSIDE METADATA
                nat (outside,outside) source dynamic GCP-HC ILB-OUTSIDE destination static ILB-OUTSIDE METADATA
                !
                call-home
                profile License
                destination transport-method http
                destination address http https://tools.cisco.com/its/service/oddce/services/DDCEService
                
                license smart
                feature tier standard
                throughput level ${var.license_throughput}
                license smart register idtoken ${var.license_token} force
                EOF

    ssh-keys = var.public_key
  }
  scheduling {
    on_host_maintenance = "MIGRATE"
    automatic_restart   = true
  }
  service_account {
    email = var.service_account_mail_id
    scopes = [
      "https://www.googleapis.com/auth/devstorage.read_only",
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring.write",
      "https://www.googleapis.com/auth/service.management.readonly",
      "https://www.googleapis.com/auth/servicecontrol",
      "https://www.googleapis.com/auth/trace.append",
    ]
  }
  depends_on = [
    google_compute_address.ilb_ip_inside,
    google_compute_address.ilb_ip_outside
  ]
}

# Instance Group Manager
resource "google_compute_region_instance_group_manager" "asav_instance_group" {
  name        = "${var.resource_name_prefix}-asav-instance-group"
  region      = var.region
  target_size = 1

  version {
    instance_template = google_compute_instance_template.asav_instance_template.self_link_unique
  }
  distribution_policy_zones = concat(var.zone1 != "" ? ["${var.region}-${var.zone1}"] : [], var.zone2 != "" ? ["${var.region}-${var.zone2}"] : [], var.zone3 != "" ? ["${var.region}-${var.zone3}"] : [])
  base_instance_name        = "${var.resource_name_prefix}-asav-cluster"
}

# Autoscaler
resource "google_compute_region_autoscaler" "asav_autoscaler" {
  name   = "${var.resource_name_prefix}-asav-autoscaler"
  target = google_compute_region_instance_group_manager.asav_instance_group.self_link
  region = var.region

  autoscaling_policy {
    max_replicas    = var.auto_scaling == true ? var.max_asa_count : var.min_asa_count
    min_replicas    = var.min_asa_count
    cooldown_period = 480
    cpu_utilization {
      target = var.cpu_utilization_target
    }
    mode = "ON"
  }
}

# ILB-Inside
resource "google_compute_region_backend_service" "asav_backend_service_ilb_inside" {
  name                  = "${var.resource_name_prefix}-asav-backend-ilb-inside"
  region                = var.region
  protocol              = var.ilb_backend_protocol
  load_balancing_scheme = "INTERNAL"
  network               = "projects/${var.project_id}/global/networks/${var.inside_vpc_name}"

  backend {
    balancing_mode = "CONNECTION"
    group = google_compute_region_instance_group_manager.asav_instance_group.instance_group
  }

  health_checks = [
    google_compute_health_check.asav_hc_ilb_inside.self_link
  ]
}

resource "google_compute_health_check" "asav_hc_ilb_inside" {
  name = "${var.resource_name_prefix}-asav-hc-ilb-inside"
  tcp_health_check {
    port = var.ilb_health_check_port
  }
  check_interval_sec  = var.ilb_check_interval_sec
  timeout_sec         = var.ilb_timeout_sec
  unhealthy_threshold = var.ilb_unhealthy_threshold
}

resource "google_compute_forwarding_rule" "asav_fr_ilb_inside" {
  name                  = "${var.resource_name_prefix}-asav-fr-ilb-inside"
  region                = var.region
  all_ports             = true
  load_balancing_scheme = "INTERNAL"
  ip_address            = google_compute_address.ilb_ip_inside.self_link
  backend_service       = google_compute_region_backend_service.asav_backend_service_ilb_inside.self_link
  network               = "projects/${var.project_id}/global/networks/${var.inside_vpc_name}"
  subnetwork            = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.inside_subnet_name}"
  ip_protocol           = contains(["TCP", "UDP"], var.ilb_backend_protocol) ? var.ilb_backend_protocol : var.ilb_frontend_protocol
}

resource "google_compute_address" "ilb_ip_inside" {
  name         = "${var.resource_name_prefix}-ilb-ip"
  address_type = "INTERNAL"
  region       = var.region
  subnetwork   = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.inside_subnet_name}"
}

# ILB-Outside
resource "google_compute_region_backend_service" "asav_backend_service_ilb_outside" {
  name                  = "${var.resource_name_prefix}-asav-backend-ilb-outside"
  region                = var.region
  protocol              = var.ilb_backend_protocol
  load_balancing_scheme = "INTERNAL"
  network               = "projects/${var.project_id}/global/networks/${var.outside_vpc_name}"

  backend {
    balancing_mode = "CONNECTION"
    group = google_compute_region_instance_group_manager.asav_instance_group.instance_group
  }

  health_checks = [
    google_compute_health_check.asav_hc_ilb_outside.self_link
  ]
}

resource "google_compute_health_check" "asav_hc_ilb_outside" {
  name = "${var.resource_name_prefix}-asav-hc-ilb-outside"
  tcp_health_check {
    port = var.ilb_health_check_port
  }
  check_interval_sec  = var.ilb_check_interval_sec
  timeout_sec         = var.ilb_timeout_sec
  unhealthy_threshold = var.ilb_unhealthy_threshold
}

resource "google_compute_forwarding_rule" "asav_fr_ilb_outside" {
  name                  = "${var.resource_name_prefix}-asav-fr-ilb-outside"
  region                = var.region
  all_ports             = true
  load_balancing_scheme = "INTERNAL"
  ip_address            = google_compute_address.ilb_ip_outside.self_link
  backend_service       = google_compute_region_backend_service.asav_backend_service_ilb_outside.self_link
  network               = "projects/${var.project_id}/global/networks/${var.outside_vpc_name}"
  subnetwork            = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.outside_subnet_name}"
  ip_protocol           = contains(["TCP", "UDP"], var.ilb_backend_protocol) ? var.ilb_backend_protocol : var.ilb_frontend_protocol
}

resource "google_compute_address" "ilb_ip_outside" {
  name         = "${var.resource_name_prefix}-ilb-ip-outside"
  address_type = "INTERNAL"
  region       = var.region
  subnetwork   = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.outside_subnet_name}"
}