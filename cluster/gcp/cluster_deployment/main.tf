provider "google" {
  project = var.project_id
  region  = var.region
}

variable "type_of_deployment" {
  validation {
    condition     = var.type_of_deployment == "east_west" || var.type_of_deployment == "north_south"
    error_message = "Invalid deployment type. Must be either 'east_west' or 'north_south'."
  }
  description = "This variable determines the type of deployment for the cluster."
}

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

variable "vpc_connector_name" {
  description = "Name for the VPC connector resource for cloud functions to access VPC resources."
  validation {
    condition     = can(regex("^[A-Za-z0-9-_]+$", var.vpc_connector_name))
    error_message = "Please provide a valid VPC connector name."
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

variable "zone1" {
  description = "The zone where the resources will be deployed."
  type        = string
  validation {
    condition     = can(regex("^[a-f]$", var.zone1))
    error_message = "Zone must be a single character between 'a' and 'f'."
  }
}

variable "zone2" {
  description = "The zone where the resources will be deployed."
  type        = string
  validation {
    condition     = can(regex("^[a-f]$", var.zone2))
    error_message = "Zone must be a single character between 'a' and 'f'."
  }
}

variable "zone3" {
  description = "The zone where the resources will be deployed."
  type        = string
  validation {
    condition     = can(regex("^[a-f]$", var.zone3))
    error_message = "Zone must be a single character between 'a' and 'f'."
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

variable "service_account_mail_id" {
  description = "Service account email used by the instances."
  validation {
    condition     = can(regex(".+@.+\\..+", var.service_account_mail_id))
    error_message = "Please provide a valid email address."
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

variable "ccl_vpc_name" {
  description = "The name of the management VPC."
  validation {
    condition     = length(var.ccl_vpc_name) > 0
    error_message = "Management VPC name cannot be empty."
  }
}

variable "ccl_subnet_name" {
  description = "Subnet name for the management VPC."
  validation {
    condition     = length(var.ccl_subnet_name) > 0
    error_message = "Please provide a valid management VPC subnet."
  }
}

variable "ccl_subnet_firstIp" {
  description = "First IP address of the CCL subnet."
  validation {
    condition     = can(regex("^((25[0-5]|2[0-4]\\d|[01]?\\d?\\d)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d?\\d)$", var.ccl_subnet_firstIp))
    error_message = "Please provide a valid IPv4 address."
  }
}

variable "ccl_subnet_lastIp" {
  description = "Last IP address of the CCL subnet."
  validation {
    condition     = can(regex("^((25[0-5]|2[0-4]\\d|[01]?\\d?\\d)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d?\\d)$", var.ccl_subnet_lastIp))
    error_message = "Please provide a valid IPv4 address."
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

variable "ccl_firewall_rule_name" {
  description = "Firewall rule name for ccl traffic."
  validation {
    condition     = can(regex("^[A-Za-z0-9-_]+$", var.ccl_firewall_rule_name))
    error_message = "Firewall rule name can only include letters, numbers, dashes, or underscores."
  }
}

variable "asav_password_secret_name" {
  description = "Name of the secret for Admin password for ASAv, Device will use this password after first time login."
  validation {
    condition     = length(var.asav_password_secret_name) > 0
    error_message = "ASAv password secret name cannot be empty."
  }
}

variable "asav_en_password_secret_name" {
  description = "Name of the secret for Enable password for ASAv, Device will used this password after first time login."
  validation {
    condition     = length(var.asav_en_password_secret_name) > 0
    error_message = "ASAv enable password secret name cannot be empty."
  }
  
}

variable "assign_public_ip_to_mgmt" {
  description = "Assign public IP to management interface."
  type        = bool
  default     = false
}

variable "auto_scaling" {
  description = "Enable or disable auto-scaling."
  type        = bool
  default     = false
}

variable "cpu_utilization_target" {
  description = "Target CPU utilization for autoscale."
  type        = number
  validation {
    condition     = var.cpu_utilization_target > 0 && var.cpu_utilization_target < 1
    error_message = "Please provide a valid CPU utilization percentage between 0 and 1."
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
    condition     = var.max_asa_count > 0
    error_message = "The max_asa_count must be greater than 0."
  }
}

variable "elb_health_check_port" {
  description = "External Load Balancer health check port."
  type        = number
  validation {
    condition     = var.elb_health_check_port > 0 && var.elb_health_check_port < 65536
    error_message = "Please provide a valid port number (1-65535)."
  }
}

variable "elb_front_end_ports" {
  description = "Range for the external load balancer ports."
  type        = string
}

variable "elb_frontend_protocol" {
  description = "Frontend protocol for the external LB (Allowed Values: TCP, UDP)."
  type = string
  validation {
    condition     = var.elb_frontend_protocol == "TCP" || var.elb_frontend_protocol == "UDP" 
    error_message = "Please provide a valid LB protocol."
  }
}

variable "elb_backend_protocol" {
  description = "Frontend protocol for the external LB (Allowed Values: TCP, UDP, UNSPECIFIED)."
  type = string
  validation {
    condition     = var.elb_backend_protocol == "TCP" || var.elb_backend_protocol == "UDP" || var.elb_backend_protocol == "UNSPECIFIED" 
    error_message = "Please provide a valid LB protocol."
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

variable "elb_check_interval_sec" {
  description = "Health check interval for the ELB."
  type        = number
  validation {
    condition     = var.elb_check_interval_sec > 0
    error_message = "Please provide a positive check interval."
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

variable "ilb_frontend_protocol" {
  description = "Frontend protocol for the internal LB (Allowed Values: TCP, UDP)."
  type = string
  validation {
    condition     = var.ilb_frontend_protocol == "TCP" || var.ilb_frontend_protocol == "UDP" 
    error_message = "Please provide a valid LB protocol."
  }
}

variable "ilb_backend_protocol" {
  description = "Frontend protocol for the internal LB (Allowed Values: TCP, UDP, UNSPECIFIED)."
  type = string
  validation {
    condition     = var.ilb_backend_protocol == "TCP" || var.ilb_backend_protocol == "UDP" || var.ilb_backend_protocol == "UNSPECIFIED" 
    error_message = "Please provide a valid LB protocol."
  }
}

variable "ilb_health_check_port" {
  description = "Internal load balancer port."
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

variable "cluster_grp_name" {
  description = "Name of the cluster group."
  validation {
    condition     = length(var.cluster_grp_name) > 0
    error_message = "Cluster group name cannot be empty."
  }
}

module "cluster_functions" {
  source = "./modules/cluster_functions"

  project_id                    = var.project_id
  region                        = var.region
  resource_name_prefix          = var.resource_name_prefix
  asav_password_secret_name     = var.asav_password_secret_name
  asav_en_password_secret_name  = var.asav_en_password_secret_name 
  service_account_mail_id       = var.service_account_mail_id
  vpc_connector_name            = var.vpc_connector_name
  license_token                 = var.license_id_token  
}

resource "time_sleep" "wait_for_function" {
  depends_on      = [module.cluster_functions]
  create_duration = "60s" # Wait for 60 seconds
}

module "north_south" {
  source = "./modules/north_south"
  count = var.type_of_deployment == "north_south" ? 1 : 0

  project_id                      = var.project_id
  region                          = var.region
  zone1                           = var.zone1
  zone2                           = var.zone2
  zone3                           = var.zone3
  resource_name_prefix            = var.resource_name_prefix
  machine_type                    = var.machine_type
  source_image_url                = var.source_image_url
  public_key                      = var.public_key
  service_account_mail_id         = var.service_account_mail_id
  outside_vpc_name                = var.outside_vpc_name
  outside_subnet_name             = var.outside_subnet_name
  inside_vpc_name                 = var.inside_vpc_name
  inside_subnet_name              = var.inside_subnet_name
  mgmt_vpc_name                   = var.mgmt_vpc_name
  mgmt_subnet_name                = var.mgmt_subnet_name
  ccl_vpc_name                    = var.ccl_vpc_name
  ccl_subnet_name                 = var.ccl_subnet_name
  ccl_subnet_firstIp              = var.ccl_subnet_firstIp
  ccl_subnet_lastIp               = var.ccl_subnet_lastIp
  inside_firewall_rule_name       = var.inside_firewall_rule_name
  outside_firewall_rule_name      = var.outside_firewall_rule_name
  mgmt_firewall_rule_name         = var.mgmt_firewall_rule_name
  ccl_firewall_rule_name          = var.ccl_firewall_rule_name
  assign_public_ip_to_mgmt        = var.assign_public_ip_to_mgmt
  auto_scaling                    = var.auto_scaling
  cpu_utilization_target          = var.cpu_utilization_target
  min_asa_count                   = var.min_asa_count
  max_asa_count                   = var.max_asa_count
  cluster_grp_name                = var.cluster_grp_name
  elb_health_check_port           = var.elb_health_check_port
  elb_front_end_ports             = var.elb_front_end_ports
  elb_frontend_protocol           = var.elb_frontend_protocol
  elb_backend_protocol            = var.elb_backend_protocol
  elb_timeout_sec                 = var.elb_timeout_sec
  elb_check_interval_sec          = var.elb_check_interval_sec
  elb_unhealthy_threshold         = var.elb_unhealthy_threshold
  ilb_frontend_protocol           = var.ilb_frontend_protocol
  ilb_backend_protocol            = var.ilb_backend_protocol
  ilb_health_check_port           = var.ilb_health_check_port
  ilb_check_interval_sec          = var.ilb_check_interval_sec
  ilb_timeout_sec                 = var.ilb_timeout_sec
  ilb_unhealthy_threshold         = var.ilb_unhealthy_threshold
  license_throughput              = var.license_throughput
  license_token                   = var.license_id_token
  
  depends_on = [resource.time_sleep.wait_for_function]
}

module "east_west" {
  source = "./modules/east_west"
  count = var.type_of_deployment == "east_west" ? 1 : 0

  project_id                      = var.project_id
  region                          = var.region
  zone1                           = var.zone1
  zone2                           = var.zone2
  zone3                           = var.zone3
  resource_name_prefix            = var.resource_name_prefix
  machine_type                    = var.machine_type
  source_image_url                = var.source_image_url
  public_key                      = var.public_key
  service_account_mail_id         = var.service_account_mail_id
  outside_vpc_name                = var.outside_vpc_name
  outside_subnet_name             = var.outside_subnet_name
  inside_vpc_name                 = var.inside_vpc_name
  inside_subnet_name              = var.inside_subnet_name
  mgmt_vpc_name                   = var.mgmt_vpc_name
  mgmt_subnet_name                = var.mgmt_subnet_name
  ccl_vpc_name                    = var.ccl_vpc_name
  ccl_subnet_name                 = var.ccl_subnet_name
  ccl_subnet_firstIp              = var.ccl_subnet_firstIp
  ccl_subnet_lastIp               = var.ccl_subnet_lastIp
  inside_firewall_rule_name       = var.inside_firewall_rule_name
  outside_firewall_rule_name      = var.outside_firewall_rule_name
  mgmt_firewall_rule_name         = var.mgmt_firewall_rule_name
  ccl_firewall_rule_name          = var.ccl_firewall_rule_name
  assign_public_ip_to_mgmt        = var.assign_public_ip_to_mgmt
  auto_scaling                    = var.auto_scaling
  cpu_utilization_target          = var.cpu_utilization_target
  min_asa_count                   = var.min_asa_count
  max_asa_count                   = var.max_asa_count
  cluster_grp_name                = var.cluster_grp_name
  ilb_frontend_protocol           = var.ilb_frontend_protocol
  ilb_backend_protocol            = var.ilb_backend_protocol
  ilb_health_check_port           = var.ilb_health_check_port
  ilb_check_interval_sec          = var.ilb_check_interval_sec
  ilb_timeout_sec                 = var.ilb_timeout_sec
  ilb_unhealthy_threshold         = var.ilb_unhealthy_threshold
  license_throughput              = var.license_throughput
  license_token                   = var.license_id_token

  depends_on = [resource.time_sleep.wait_for_function]
}
