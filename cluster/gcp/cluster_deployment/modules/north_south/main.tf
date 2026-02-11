# Variables
variable "service_account_mail_id" {}
variable "project_id" {}
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

variable "elb_backend_protocol" {}
variable "elb_frontend_protocol" {}
variable "ilb_backend_protocol" {}
variable "ilb_frontend_protocol" {}

variable "ilb_health_check_port" {}
variable "ilb_check_interval_sec" {}
variable "ilb_timeout_sec" {}
variable "ilb_unhealthy_threshold" {}

variable "elb_check_interval_sec" {}
variable "elb_health_check_port" {}
variable "elb_timeout_sec" {}
variable "elb_unhealthy_threshold" {}
variable "elb_front_end_ports" {}

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
      for_each = var.assign_public_ip_to_mgmt ? [1] : [0]
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
                object network ILB
                host ${google_compute_address.ilb_ip.address}
                object network ELB
                host ${google_compute_address.elb_ip.address}
                ! Nat Rules
                nat (inside,outside) source dynamic GCP-HC ILB destination static ILB METADATA
                nat (outside,outside) source dynamic GCP-HC ELB destination static ELB METADATA
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
    google_compute_address.elb_ip,
    google_compute_address.ilb_ip
  ]
}

# Instance Group Manager
resource "google_compute_region_instance_group_manager" "asav_instance_group" {
  name   = "${var.resource_name_prefix}-asav-instance-group"
  region = var.region
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
    cooldown_period = 60
    cpu_utilization {
      target = var.cpu_utilization_target
    }
    mode = "ON"
  }
}

#ELB
resource "google_compute_region_backend_service" "asav_backend_service_elb" {
  name                  = "${var.resource_name_prefix}-asav-backend-service-elb"
  region                = var.region
  port_name             = "tcp"
  protocol              = var.elb_backend_protocol
  load_balancing_scheme = "EXTERNAL"

  backend {
    balancing_mode = "CONNECTION"
    group = google_compute_region_instance_group_manager.asav_instance_group.instance_group
  }

  health_checks = [
    google_compute_region_health_check.asav_hc_elb.self_link
  ]
}

resource "google_compute_region_health_check" "asav_hc_elb" {
  name   = "${var.resource_name_prefix}-asav-hc-elb"
  region = var.region

  tcp_health_check {
    port         = var.elb_health_check_port
    proxy_header = "NONE"
  }
  check_interval_sec  = var.elb_check_interval_sec
  timeout_sec         = var.elb_timeout_sec
  unhealthy_threshold = var.elb_unhealthy_threshold
}

resource "google_compute_forwarding_rule" "asav_fr_elb" {
  count = var.elb_front_end_ports == "all" ? 0 : 1
  
  name                  = "${var.resource_name_prefix}-asav-fr-elb"
  region                = var.region
  ip_protocol           = var.elb_frontend_protocol
  load_balancing_scheme = "EXTERNAL"
  ip_address            = google_compute_address.elb_ip.self_link
  backend_service       = google_compute_region_backend_service.asav_backend_service_elb.self_link

  ports = var.elb_front_end_ports

  depends_on = [
    google_compute_region_backend_service.asav_backend_service_elb,
    google_compute_address.elb_ip
  ]
}
resource "google_compute_forwarding_rule" "asav_fr_elb1" {
  count = var.elb_front_end_ports == "all" ? 1 : 0

  name                  = "${var.resource_name_prefix}-asav-fr-elb"
  region                = var.region
  ip_protocol           = var.elb_frontend_protocol
  load_balancing_scheme = "EXTERNAL"
  ip_address            = google_compute_address.elb_ip.self_link
  backend_service       = google_compute_region_backend_service.asav_backend_service_elb.self_link

  all_ports = true
  
  depends_on = [
    google_compute_region_backend_service.asav_backend_service_elb,
    google_compute_address.elb_ip
  ]
}

resource "google_compute_address" "elb_ip" {
  name         = "${var.resource_name_prefix}-elb-ip"
  address_type = "EXTERNAL"
  region       = var.region
}

# ILB
resource "google_compute_region_backend_service" "asav_backend_service_ilb" {
  name                  = "${var.resource_name_prefix}-asav-backend-service-ilb"
  region                = var.region
  protocol              = var.ilb_backend_protocol
  load_balancing_scheme = "INTERNAL"
  network               = "projects/${var.project_id}/global/networks/${var.inside_vpc_name}"

  backend {
    balancing_mode = "CONNECTION"
    group = google_compute_region_instance_group_manager.asav_instance_group.instance_group
  }

  health_checks = [
    google_compute_health_check.asav_hc_ilb.self_link
  ]
}

resource "google_compute_health_check" "asav_hc_ilb" {
  name = "${var.resource_name_prefix}-asav-hc-ilb"
  tcp_health_check {
    port = var.ilb_health_check_port
  }
  check_interval_sec  = var.ilb_check_interval_sec
  timeout_sec         = var.ilb_timeout_sec
  unhealthy_threshold = var.ilb_unhealthy_threshold
}

resource "google_compute_forwarding_rule" "asav_fr_ilb" {
  name                  = "${var.resource_name_prefix}-asav-fr-ilb"
  region                = var.region
  all_ports             = true
  load_balancing_scheme = "INTERNAL"
  ip_address            = google_compute_address.ilb_ip.self_link
  backend_service       = google_compute_region_backend_service.asav_backend_service_ilb.self_link
  network               = "projects/${var.project_id}/global/networks/${var.inside_vpc_name}"
  subnetwork            = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.inside_subnet_name}"
}

resource "google_compute_address" "ilb_ip" {
  name         = "${var.resource_name_prefix}-ilb-ip"
  address_type = "INTERNAL"
  region      = var.region
  subnetwork   = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.inside_subnet_name}"
}

resource "google_compute_router" "cloud_nat_router" {
  name    = "${var.resource_name_prefix}-cloud-nat-router"
  region  = var.region
  network = "projects/${var.project_id}/global/networks/${var.outside_vpc_name}"
}

resource "google_compute_router_nat" "cloud_nat" {
  name   = "${var.resource_name_prefix}-cloud-nat"
  router = google_compute_router.cloud_nat_router.name
  region = var.region

  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}