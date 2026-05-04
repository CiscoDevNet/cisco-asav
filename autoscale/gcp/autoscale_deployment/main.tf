provider "google" {
  project = var.project_id
  region  = var.region
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

variable "assign_public_ip_to_mgmt" {
  description = "Assign public IP to management interface."
  type        = bool
  default     = false
}

variable "enable_secure_boot" {
  description = "Enable Secure Boot for the ASAv instances (supported from version 9.24 onwards)."
  type        = bool
  default     = false
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
    condition     = can(regex("^[a-z](,[a-z]){0,2}$", var.zone))
    error_message = "Please provide a valid zone or comma-separated list of up to 3 zones."
  }
}


module "asav_functions" {
  source                  = "./modules/functions"
  project_id              = var.project_id
  region                  = var.region
  resource_name_prefix    = var.resource_name_prefix
  service_account_mail_id = var.service_account_mail_id
  vpc_connector_name      = var.vpc_connector_name
}

module "asav_autoscale" {
  source                          = "./modules/north_south"
  project_id                      = var.project_id
  region                          = var.region
  resource_name_prefix            = var.resource_name_prefix
  machine_type                    = var.machine_type
  source_image_url                = var.source_image_url
  public_key                      = var.public_key
  service_account_mail_id         = var.service_account_mail_id
  assign_public_ip_to_mgmt        = var.assign_public_ip_to_mgmt
  enable_secure_boot              = var.enable_secure_boot
  cpu_utilization_target          = var.cpu_utilization_target
  cool_down_period_sec            = var.cool_down_period_sec
  min_asa_count                   = var.min_asa_count
  max_asa_count                   = var.max_asa_count
  elb_health_check_port           = var.elb_health_check_port
  elb_port_range                  = var.elb_port_range
  elb_port_name                   = var.elb_port_name
  elb_protocol                    = var.elb_protocol
  elb_protocol_name               = var.elb_protocol_name
  elb_ip_protocol                 = var.elb_ip_protocol
  elb_timeout_sec                 = var.elb_timeout_sec
  elb_unhealthy_threshold         = var.elb_unhealthy_threshold
  ilb_protocol                    = var.ilb_protocol
  ilb_protocol_name               = var.ilb_protocol_name
  ilb_health_check_port           = var.ilb_health_check_port
  ilb_check_interval_sec          = var.ilb_check_interval_sec
  ilb_timeout_sec                 = var.ilb_timeout_sec
  ilb_unhealthy_threshold         = var.ilb_unhealthy_threshold
  ilb_draining_timeout_sec        = var.ilb_draining_timeout_sec
  outside_vpc_name                = var.outside_vpc_name
  outside_subnet_name             = var.outside_subnet_name
  inside_vpc_name                 = var.inside_vpc_name
  inside_subnet_name              = var.inside_subnet_name
  mgmt_vpc_name                   = var.mgmt_vpc_name
  mgmt_subnet_name                = var.mgmt_subnet_name
  inside_firewall_rule_name       = var.inside_firewall_rule_name
  outside_firewall_rule_name      = var.outside_firewall_rule_name
  mgmt_firewall_rule_name         = var.mgmt_firewall_rule_name
  health_check_firewall_rule_name = var.health_check_firewall_rule_name
  appserver_ip                    = var.appserver_ip
  license_id_token                = var.license_id_token
  license_throughput              = var.license_throughput
  zone                            = var.zone

  depends_on = [module.asav_functions]
}

# Outputs

output "elb_name" {
  value = module.asav_autoscale.elb_name
}

output "ilb_name" {
  value = module.asav_autoscale.ilb_name
}

output "elb_ip" {
  value = module.asav_autoscale.elb_ip
}

output "ilb_ip" {
  value = module.asav_autoscale.ilb_ip
}

output "outside_nat_router" {
  value = module.asav_autoscale.outside_nat_router
}

output "outside_nat" {
  value = module.asav_autoscale.outside_nat
}

output "instance_group_name" {
  value = module.asav_autoscale.instance_group_name
}

output "scale_out_function_name" {
  value = module.asav_functions.scale_out_function_name
}

output "scale_in_function_name" {
  value = module.asav_functions.scale_in_function_name
}