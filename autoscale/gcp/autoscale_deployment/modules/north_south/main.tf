variable "project_id" {
  description = "The ID of the GCP project to use."
  validation {
    condition = (
      length(var.project_id) > 2 &&
      can(regex("^[0-9A-Za-z-]+$", var.project_id))
    )
    error_message = "Please provide a valid project ID."
  }
}

variable "resource_name_prefix" {
  description = "Prefix for naming resources in the deployment."
  validation {
    condition = (
      can(regex("^[a-zA-Z][0-9A-Za-z-_]*$", var.resource_name_prefix)) &&
      length(var.resource_name_prefix) > 1
    )
    error_message = "Prefix must start with a letter and contain only letters, numbers, dashes, or underscores."
  }
}

variable "region" {
  description = "The GCP region to create resources in."
  validation {
    condition = (
      length(var.region) > 2 &&
      can(regex("^[0-9A-Za-z-]+$", var.region))
    )
    error_message = "Please provide a valid region."
  }
}

variable "machine_type" {
  description = "Machine type for the instances."
  validation {
    condition     = can(regex("^[A-Za-z0-9-]+$", var.machine_type))
    error_message = "Please provide a valid machine type."
  }
}

variable "source_image_url" {
  description = "URL to the source image used by instances."
  validation {
    condition     = can(regex("^(https?://|projects/).+", var.source_image_url))
    error_message = "Please provide a valid URL starting with http or https, or a valid GCP image reference beginning with projects/."
  }
}

variable "public_key" {
  description = "SSH public key for instance access."
  validation {
    condition     = can(regex("^(ssh-(rsa|dss|ed25519|ecdsa)\\s.+)$", var.public_key))
    error_message = "Please provide a valid SSH public key."
  }
}

variable "assign_public_ip_to_mgmt" {
  description = "Assign public IP to management interface."
  type        = bool
}

variable "enable_secure_boot" {
  description = "Enable Secure Boot for ASAv instances (supported from version 9.24 onwards)."
  type        = bool
}

variable "service_account_mail_id" {
  description = "Service account email used by the instances."
  validation {
    condition     = can(regex(".+@.+\\..+", var.service_account_mail_id))
    error_message = "Please provide a valid email address."
  }
}

variable "cpu_utilization_target" {
  description = "Target CPU utilization for autoscale."
  type        = number
  validation {
    condition     = var.cpu_utilization_target > 0 && var.cpu_utilization_target < 1
    error_message = "Please provide a valid CPU utilization percentage between 0 and 1."
  }
}

variable "cool_down_period_sec" {
  description = "Scale-in/out cooldown period in seconds."
  type        = number
  validation {
    condition     = var.cool_down_period_sec > 0
    error_message = "Please provide a positive cooldown period."
  }
}

variable "min_asa_count" {
  description = "Minimum number of ASAv instances."
  type        = number
  validation {
    condition     = var.min_asa_count >= 0
    error_message = "Minimum ASAv count cannot be negative."
  }
}

variable "max_asa_count" {
  description = "The maximum ASA count allowed."
  type        = number
  validation {
    condition     = var.max_asa_count >= 0
    error_message = "The max_asa_count must be greater than or equal to 0."
  }
}

variable "elb_health_check_port" {
  description = "External load balancer health-check port."
  type        = number
  validation {
    condition     = var.elb_health_check_port > 0 && var.elb_health_check_port < 65536
    error_message = "Please provide a valid port number (1-65535)."
  }
}

variable "elb_port_range" {
  description = "Range for the external load balancer ports."
  type        = string
  validation {
    condition     = can(regex("^\\d+(?:-\\d+)?$", var.elb_port_range))
    error_message = "Please provide a valid port range (1-65535), e.g., 80-80."
  }
}

variable "elb_port_name" {
  description = "Port name for the external LB."
  validation {
    condition     = can(regex("^[A-Za-z0-9-]+$", var.elb_port_name))
    error_message = "Port name can only include letters, numbers, or dashes."
  }
}

variable "elb_protocol" {
  description = "Protocol for the external LB (e.g., TCP)."
  validation {
    condition     = length(var.elb_protocol) > 2
    error_message = "Please provide a valid LB protocol."
  }
}

variable "elb_protocol_name" {
  description = "Protocol name for the external LB."
  validation {
    condition     = can(regex("^[A-Za-z0-9-]+$", var.elb_protocol_name))
    error_message = "Protocol name can only include letters, numbers, or dashes."
  }
}

variable "elb_ip_protocol" {
  description = "IP protocol used by the external LB."
  validation {
    condition     = length(var.elb_ip_protocol) > 2
    error_message = "Please provide a valid IP protocol name."
  }
}

variable "elb_timeout_sec" {
  description = "Timeout for the external LB in seconds."
  type        = number
  validation {
    condition     = var.elb_timeout_sec > 0
    error_message = "Please provide a valid LB timeout in seconds."
  }
}

variable "elb_unhealthy_threshold" {
  description = "Unhealthy threshold for the external LB."
  type        = number
  validation {
    condition     = var.elb_unhealthy_threshold > 0
    error_message = "Please provide a valid unhealthy threshold."
  }
}

variable "ilb_protocol" {
  description = "Protocol for the internal LB."
  validation {
    condition     = length(var.ilb_protocol) > 2
    error_message = "Please provide a valid LB protocol."
  }
}

variable "ilb_protocol_name" {
  description = "Protocol name for the internal LB."
  validation {
    condition     = can(regex("^[A-Za-z0-9-]+$", var.ilb_protocol_name))
    error_message = "Protocol name can only include letters, numbers, or dashes."
  }
}

variable "ilb_health_check_port" {
  description = "Internal load balancer health-check port."
  type        = number
  validation {
    condition     = var.ilb_health_check_port > 0 && var.ilb_health_check_port < 65536
    error_message = "Please provide a valid port number (1-65535)."
  }
}

variable "ilb_check_interval_sec" {
  description = "Health check interval for the ILB."
  type        = number
  validation {
    condition     = var.ilb_check_interval_sec > 0
    error_message = "Please provide a positive check interval."
  }
}

variable "ilb_timeout_sec" {
  description = "Timeout for the internal LB in seconds."
  type        = number
  validation {
    condition     = var.ilb_timeout_sec > 0
    error_message = "Please provide a valid LB timeout in seconds."
  }
}

variable "ilb_unhealthy_threshold" {
  description = "Unhealthy threshold for the internal LB."
  type        = number
  validation {
    condition     = var.ilb_unhealthy_threshold > 0
    error_message = "Please provide a valid unhealthy threshold."
  }
}

variable "ilb_draining_timeout_sec" {
  description = "Draining timeout for the internal LB in seconds."
  type        = number
  validation {
    condition     = var.ilb_draining_timeout_sec >= 0
    error_message = "Draining timeout cannot be negative."
  }
}

variable "outside_vpc_name" {
  description = "The name of the outside VPC."
  validation {
    condition     = length(var.outside_vpc_name) > 0
    error_message = "Outside VPC name cannot be empty."
  }
}

variable "outside_subnet_name" {
  description = "Subnet name for the outside VPC."
  validation {
    condition     = length(var.outside_subnet_name) > 0
    error_message = "Please provide a valid outside VPC subnet ID or name."
  }
}

variable "inside_vpc_name" {
  description = "The name of the inside VPC."
  validation {
    condition     = length(var.inside_vpc_name) > 0
    error_message = "Inside VPC name cannot be empty."
  }
}

variable "inside_subnet_name" {
  description = "Subnet name for the inside VPC."
  validation {
    condition     = length(var.inside_subnet_name) > 0
    error_message = "Please provide a valid inside VPC subnet ID or name."
  }
}

variable "mgmt_vpc_name" {
  description = "The name of the management VPC."
  validation {
    condition     = length(var.mgmt_vpc_name) > 0
    error_message = "Management VPC name cannot be empty."
  }
}

variable "mgmt_subnet_name" {
  description = "Subnet name for the management VPC."
  validation {
    condition     = length(var.mgmt_subnet_name) > 0
    error_message = "Please provide a valid management VPC subnet."
  }
}


variable "appserver_ip" {
  description = "IP address of the application server."
  validation {
    condition     = can(regex("^((25[0-5]|2[0-4]\\d|[01]?\\d?\\d)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d?\\d)$", var.appserver_ip))
    error_message = "Please provide a valid IPv4 address."
  }
}

variable "license_id_token" {
  description = "License ID token for ASAv."
  validation {
    condition     = length(var.license_id_token) > 0
    error_message = "License ID token cannot be empty."
  }
}

variable "license_throughput" {
  description = "License throughput for ASAv. allowed values: 100M, 1G, 2G, 10G, 20G etc."
  type        = string
  validation {
    condition     = length(var.license_throughput) > 0
    error_message = "Please provide a valid license throughput."
  }
}

variable "inside_firewall_rule_name" {
  description = "Firewall rule name for inside traffic."
  validation {
    condition     = can(regex("^[A-Za-z0-9-_]+$", var.inside_firewall_rule_name))
    error_message = "Firewall rule name can only include letters, numbers, dashes, or underscores."
  }
}

variable "outside_firewall_rule_name" {
  description = "Firewall rule name for outside traffic."
  validation {
    condition     = can(regex("^[A-Za-z0-9-_]+$", var.outside_firewall_rule_name))
    error_message = "Firewall rule name can only include letters, numbers, dashes, or underscores."
  }
}

variable "mgmt_firewall_rule_name" {
  description = "Firewall rule name for management traffic."
  validation {
    condition     = can(regex("^[A-Za-z0-9-_]+$", var.mgmt_firewall_rule_name))
    error_message = "Firewall rule name can only include letters, numbers, dashes, or underscores."
  }
}

variable "health_check_firewall_rule_name" {
  description = "Firewall rule for LB health checks."
  validation {
    condition     = can(regex("^[A-Za-z0-9-_]+$", var.health_check_firewall_rule_name))
    error_message = "Firewall rule name can only include letters, numbers, dashes, or underscores."
  }
}

variable "zone" {
  # Zone is string "a,b,c,d" or "a"
  description = "The zone where the resources will be deployed."
  type        = string
  validation {
    condition     = can(regex("^[a-z](,[a-z])*$", var.zone))
    error_message = "Please provide a valid zone or comma-separated list of zones."
  }
}

data "google_compute_subnetwork" "inside_vpc_subnet" {
  name = var.inside_subnet_name
}

data "google_compute_subnetwork" "mgmt_vpc_subnet" {
  name = var.mgmt_subnet_name
}


resource "google_compute_instance_template" "asav_instance_template" {
  name           = "${var.resource_name_prefix}-asav-instance-template"
  machine_type   = var.machine_type
  can_ip_forward = true
  disk {
    boot         = true
    auto_delete  = true
    type         = "PERSISTENT"
    disk_type    = "pd-standard"
    source_image = var.source_image_url
  }

  tags = [
    var.inside_firewall_rule_name,
    var.outside_firewall_rule_name,
    var.mgmt_firewall_rule_name,
    var.health_check_firewall_rule_name
  ]
  # Three NICs (inside, outside, management)
  network_interface {
    network    = "projects/${var.project_id}/global/networks/${var.outside_vpc_name}"
    subnetwork = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.outside_subnet_name}"
  }
  network_interface {
    network    = "projects/${var.project_id}/global/networks/${var.inside_vpc_name}"
    subnetwork = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.inside_subnet_name}"
  }
  network_interface {
    network    = "projects/${var.project_id}/global/networks/${var.mgmt_vpc_name}"
    subnetwork = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.mgmt_subnet_name}"
    dynamic "access_config" {
      for_each = var.assign_public_ip_to_mgmt ? [1] : []
      content {}
    }
  }

  reservation_affinity {
    type = "ANY_RESERVATION"
  }

  shielded_instance_config {
    enable_secure_boot          = var.enable_secure_boot
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    startup-script = <<-EOT
          !Interface Config
          interface G0/0
          nameif inside
          security-level 100
          ip address dhcp
          no shutdown

          interface G0/1
          nameif management
          security-level 50
          ip address dhcp
          no shutdown

          interface M0/0
          no management-only
          nameif outside
          security-level 0
          ip address dhcp setroute
          no shutdown
          !
          same-security-traffic permit inter-interface
          same-security-traffic permit intra-interface
          !
          !Due to load balancer limitation in GCP, 
          !"GigabitEthernet0/1" will be used as a Management interface 
          !"Management0/0" will be used as a data interface
          crypto key generate rsa modulus 2048
          ssh 0.0.0.0 0.0.0.0 management
          ssh version 2
          ssh timeout 60
          ssh scopy enable
          aaa authentication ssh console LOCAL
          !ssh authentication publickey ${var.public_key}
          username admin privilege 15
          username admin attributes
          service-type admin

          ! required config end
          dns domain-lookup outside
          dns server-group DefaultDNS
          name-server 8.8.8.8
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
          object network ILB-SOUTH
          host ${google_compute_address.asav_ilb_ip.address}
          object network ELB-NORTH
          host ${google_compute_address.asav_elb_ip.address}
          object network appServer
          host ${var.appserver_ip}
          object network any4
          subnet 0.0.0.0 0.0.0.0
          ! Nat Rules
          nat (inside,outside) source dynamic GCP-HC ILB-SOUTH destination static ILB-SOUTH METADATA
          nat (outside,outside) source dynamic GCP-HC ELB-NORTH destination static ELB-NORTH METADATA
          nat (inside,outside) source dynamic any4 interface
          !
          object network appServer
          nat (inside,outside) static ${google_compute_address.asav_elb_ip.address}
          ! object network any4
          ! nat (outside,inside) dynamic interface
          ! Route Add
          route inside 0.0.0.0 0.0.0.0 ${data.google_compute_subnetwork.inside_vpc_subnet.gateway_address} 2
          route management 0.0.0.0 0.0.0.0 ${data.google_compute_subnetwork.mgmt_vpc_subnet.gateway_address} 3
          call-home
          profile License
          destination transport-method http
          destination address http https://tools.cisco.com/its/service/oddce/services/DDCEService
          license smart
          feature tier standard
          throughput level ${var.license_throughput}
          license smart register idtoken ${var.license_id_token} force
    EOT
    ssh-keys       = var.public_key
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

}

resource "google_compute_region_instance_group_manager" "asav_instance_group" {
  name               = "${var.resource_name_prefix}-asav-instance-group"
  region             = var.region
  base_instance_name = "${var.resource_name_prefix}-asav-instance"
  target_size        = 1

  distribution_policy_zones = [for zone in split(",", var.zone) : "${var.region}-${zone}"]
  version {
    name              = "v1"
    instance_template = google_compute_instance_template.asav_instance_template.id
  }
}

resource "google_compute_region_autoscaler" "asav_autoscaler" {
  name   = "${var.resource_name_prefix}-asav-autoscaler"
  region = var.region
  target = google_compute_region_instance_group_manager.asav_instance_group.id
  autoscaling_policy {
    mode            = "ON"
    max_replicas    = var.max_asa_count
    min_replicas    = var.min_asa_count
    cooldown_period = var.cool_down_period_sec
    cpu_utilization {
      target = var.cpu_utilization_target
    }
  }
}

resource "google_compute_region_backend_service" "asav_backend_service_elb" {
  name                  = "${var.resource_name_prefix}-asav-backend-service-elb"
  region                = var.region
  port_name             = var.elb_port_name
  protocol              = var.elb_protocol
  load_balancing_scheme = "EXTERNAL"
  backend {
    group          = google_compute_region_instance_group_manager.asav_instance_group.instance_group
    balancing_mode = "CONNECTION"
  }
  health_checks = [google_compute_region_health_check.asav_hc_elb.id]
}

resource "google_compute_region_health_check" "asav_hc_elb" {
  name   = "${var.resource_name_prefix}-asav-hc-elb"
  region = var.region
  tcp_health_check {
    port         = var.elb_health_check_port
    proxy_header = "NONE"
  }
  timeout_sec = var.elb_timeout_sec
  # type                = var.elb_protocol_name
  unhealthy_threshold = var.elb_unhealthy_threshold
}

resource "google_compute_forwarding_rule" "asav_fr_elb" {
  name                  = "${var.resource_name_prefix}-asav-fr-elb"
  region                = var.region
  load_balancing_scheme = "EXTERNAL"
  ip_protocol           = var.elb_ip_protocol
  port_range            = var.elb_port_range
  backend_service       = google_compute_region_backend_service.asav_backend_service_elb.id
  ip_address            = google_compute_address.asav_elb_ip.address
}

resource "google_compute_address" "asav_elb_ip" {
  name         = "${var.resource_name_prefix}-elb-ip"
  region       = var.region
  address_type = "EXTERNAL"
}

resource "google_compute_region_backend_service" "asav_backend_service_ilb" {
  name                  = "${var.resource_name_prefix}-asav-backend-service-ilb"
  region                = var.region
  protocol              = var.ilb_protocol
  load_balancing_scheme = "INTERNAL"
  backend {
    group          = google_compute_region_instance_group_manager.asav_instance_group.instance_group
    balancing_mode = "CONNECTION"
  }
  health_checks                   = [google_compute_health_check.asav_hc_ilb.id]
  connection_draining_timeout_sec = var.ilb_draining_timeout_sec
  network                         = "projects/${var.project_id}/global/networks/${var.inside_vpc_name}"
}

resource "google_compute_health_check" "asav_hc_ilb" {
  name = "${var.resource_name_prefix}-asav-hc-ilb"
  tcp_health_check {
    port = var.ilb_health_check_port
  }
  check_interval_sec = var.ilb_check_interval_sec
  timeout_sec        = var.ilb_timeout_sec
  # type                 = var.ilb_protocol_name
  unhealthy_threshold = var.ilb_unhealthy_threshold
}

resource "google_compute_forwarding_rule" "asav_fr_ilb" {
  name                  = "${var.resource_name_prefix}-asav-fr-ilb"
  region                = var.region
  load_balancing_scheme = "INTERNAL"
  all_ports             = true
  ip_address            = google_compute_address.asav_ilb_ip.address
  backend_service       = google_compute_region_backend_service.asav_backend_service_ilb.id
  network               = "projects/${var.project_id}/global/networks/${var.inside_vpc_name}"
  subnetwork            = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.inside_subnet_name}"
}

resource "google_compute_address" "asav_ilb_ip" {
  name         = "${var.resource_name_prefix}-ilb-ip"
  region       = var.region
  address_type = "INTERNAL"
  subnetwork   = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.inside_subnet_name}"
}
resource "google_compute_router" "outside_nat_router" {
  name    = "${var.resource_name_prefix}-out-nat-router"
  region  = var.region
  network = "projects/${var.project_id}/global/networks/${var.outside_vpc_name}"

}

resource "google_compute_router_nat" "outside_nat" {
  name                               = "${var.resource_name_prefix}-out-nat"
  router                             = google_compute_router.outside_nat_router.name
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}

# Outputs
output "elb_name" {
  value = google_compute_forwarding_rule.asav_fr_elb.name
}

output "ilb_name" {
  value = google_compute_forwarding_rule.asav_fr_ilb.name
}

output "elb_ip" {
  value = google_compute_address.asav_elb_ip.address
}

output "ilb_ip" {
  value = google_compute_address.asav_ilb_ip.address
}

output "outside_nat_router" {
  value = google_compute_router.outside_nat_router.name
}

output "outside_nat" {
  value = google_compute_router_nat.outside_nat.name
}

output "instance_group_name" {
  value = google_compute_region_instance_group_manager.asav_instance_group.name
}