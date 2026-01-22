# OCI Network Infrastructure Terraform Template
# Creates 4 VCNs (Management, Diagnostic, Inside, Outside) with complete networking

terraform {
  required_version = ">= 1.0"
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = "~> 5.0"
    }
  }
}

# Input Variables
variable "tenancy_ocid" {
  description = "OCID of the tenancy"
  type        = string
}

variable "region" {
  description = "OCI region"
  type        = string
  default     = "us-phoenix-1"
}

variable "compartment_id" {
  description = "OCID of the compartment where resources will be created"
  type        = string
}

variable "prefix" {
  description = "Prefix for resource naming"
  type        = string
}

# Cisco NAT Pool IP ranges for security rules
variable "cisco_nat_pool_ipv4" {
  description = "Cisco NAT Pool IPv4 CIDR blocks for security rules"
  type        = list(string)
}

variable "cisco_nat_pool_ipv6" {
  description = "Cisco NAT Pool IPv6 CIDR blocks for security rules"
  type        = list(string)
}

# Network CIDR Configuration
variable "management_vcn_cidr" {
  description = "CIDR block for Management VCN"
  type        = string
}

variable "management_subnet_cidr" {
  description = "CIDR block for Management subnet"
  type        = string
}

variable "diagnostic_vcn_cidr" {
  description = "CIDR block for Diagnostic VCN"
  type        = string
}

variable "diagnostic_subnet_cidr" {
  description = "CIDR block for Diagnostic subnet"
  type        = string
}

variable "inside_vcn_cidr" {
  description = "CIDR block for Inside VCN"
  type        = string
}

variable "inside_subnet_cidr" {
  description = "CIDR block for Inside subnet"
  type        = string
}

variable "outside_vcn_cidr" {
  description = "CIDR block for Outside VCN"
  type        = string
}

variable "outside_subnet_cidr" {
  description = "CIDR block for Outside subnet"
  type        = string
}

variable "create_function_subnet" {
  description = "Whether to create function subnet for autoscale deployment"
  type        = bool
  default     = false
}

variable "function_vcn_cidr" {
  description = "CIDR block for Function VCN"
  type        = string
  default     = ""
}

variable "function_subnet_cidr" {
  description = "CIDR block for Function subnet"
  type        = string
  default     = ""
}


# Provider Configuration
provider "oci" {
  tenancy_ocid = var.tenancy_ocid
  region       = var.region
}

# Data source to get compartment information
data "oci_identity_compartment" "target_compartment" {
  id = var.compartment_id
}

# Management Network
resource "oci_core_vcn" "management_vcn" {
  compartment_id = var.compartment_id
  cidr_blocks    = [var.management_vcn_cidr]
  display_name   = "${var.prefix}-mgmt-vcn"
  dns_label      = "managementvcn"
  is_ipv6enabled = true

  lifecycle {
    ignore_changes = [defined_tags]
  }

  freeform_tags = {
    Environment = "test"
    Purpose     = "management"
    Prefix      = var.prefix
  }
}

resource "oci_core_internet_gateway" "management_igw" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.management_vcn.id
  display_name   = "${var.prefix}-mgmt-vcn-igw"
  enabled        = true
}

resource "oci_core_route_table" "management_rt" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.management_vcn.id
  display_name   = "${var.prefix}-mgmt-vcn-rt"

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.management_igw.id
    description       = "Default IPv4 route"
  }

  dynamic "route_rules" {
    for_each = [1]
    content {
      destination       = "::/0"
      destination_type  = "CIDR_BLOCK"
      network_entity_id = oci_core_internet_gateway.management_igw.id
      description       = "Default IPv6 route"
    }
  }
}

resource "oci_core_security_list" "management_sl" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.management_vcn.id
  display_name   = "${var.prefix}-mgmt-vcn-sl"

  # Cisco NAT Pool IPv4 ingress rules
  dynamic "ingress_security_rules" {
    for_each = var.cisco_nat_pool_ipv4
    content {
      protocol    = "all"
      source      = ingress_security_rules.value
      source_type = "CIDR_BLOCK"
      description = "Allow traffic from Cisco NAT Pool IPv4: ${ingress_security_rules.value}"
    }
  }

  # Cisco NAT Pool IPv6 ingress rules
  dynamic "ingress_security_rules" {
    for_each = var.cisco_nat_pool_ipv6
    content {
      protocol    = "all"
      source      = ingress_security_rules.value
      source_type = "CIDR_BLOCK"
      description = "Allow traffic from Cisco NAT Pool IPv6: ${ingress_security_rules.value}"
    }
  }

  egress_security_rules {
    protocol         = "all"
    destination      = "0.0.0.0/0"
    destination_type = "CIDR_BLOCK"
    description      = "Allow all IPv4 egress traffic"
  }

  dynamic "egress_security_rules" {
    for_each = [1]
    content {
      protocol         = "all"
      destination      = "::/0"
      destination_type = "CIDR_BLOCK"
      description      = "Allow all IPv6 egress traffic"
    }
  }
}

resource "oci_core_subnet" "management_subnet" {
  compartment_id    = var.compartment_id
  vcn_id            = oci_core_vcn.management_vcn.id
  cidr_block        = var.management_subnet_cidr
  display_name      = "${var.prefix}-mgmt-subnet"
  dns_label         = "managementsub"
  route_table_id    = oci_core_route_table.management_rt.id
  security_list_ids = [oci_core_security_list.management_sl.id]
  ipv6cidr_block = length(oci_core_vcn.management_vcn.ipv6cidr_blocks) > 0 ? cidrsubnet(oci_core_vcn.management_vcn.ipv6cidr_blocks[0], 8, 0) : null
}

resource "oci_core_network_security_group" "management_nsg" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.management_vcn.id
  display_name   = "${var.prefix}-mgmt-nsg"
}

# Diagnostic Network
resource "oci_core_vcn" "diagnostic_vcn" {
  compartment_id = var.compartment_id
  cidr_blocks    = [var.diagnostic_vcn_cidr]
  display_name   = "${var.prefix}-diag-vcn"
  dns_label      = "diagnosticvcn"
  is_ipv6enabled = true

  lifecycle {
    ignore_changes = [defined_tags]
  }

  freeform_tags = {
    Environment = "test"
    Purpose     = "diagnostic"
    Prefix      = var.prefix
  }
}

resource "oci_core_internet_gateway" "diagnostic_igw" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.diagnostic_vcn.id
  display_name   = "${var.prefix}-diag-vcn-igw"
  enabled        = true
}

resource "oci_core_route_table" "diagnostic_rt" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.diagnostic_vcn.id
  display_name   = "${var.prefix}-diag-vcn-rt"

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.diagnostic_igw.id
    description       = "Default IPv4 route"
  }

  dynamic "route_rules" {
    for_each = [1]
    content {
      destination       = "::/0"
      destination_type  = "CIDR_BLOCK"
      network_entity_id = oci_core_internet_gateway.diagnostic_igw.id
      description       = "Default IPv6 route"
    }
  }
}

resource "oci_core_security_list" "diagnostic_sl" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.diagnostic_vcn.id
  display_name   = "${var.prefix}-diag-vcn-sl"

  # Cisco NAT Pool IPv4 ingress rules
  dynamic "ingress_security_rules" {
    for_each = var.cisco_nat_pool_ipv4
    content {
      protocol    = "all"
      source      = ingress_security_rules.value
      source_type = "CIDR_BLOCK"
      description = "Allow traffic from Cisco NAT Pool IPv4: ${ingress_security_rules.value}"
    }
  }

  # Cisco NAT Pool IPv6 ingress rules
  dynamic "ingress_security_rules" {
    for_each = var.cisco_nat_pool_ipv6
    content {
      protocol    = "all"
      source      = ingress_security_rules.value
      source_type = "CIDR_BLOCK"
      description = "Allow traffic from Cisco NAT Pool IPv6: ${ingress_security_rules.value}"
    }
  }

  egress_security_rules {
    protocol         = "all"
    destination      = "0.0.0.0/0"
    destination_type = "CIDR_BLOCK"
    description      = "Allow all IPv4 egress traffic"
  }

  dynamic "egress_security_rules" {
    for_each = [1]
    content {
      protocol         = "all"
      destination      = "::/0"
      destination_type = "CIDR_BLOCK"
      description      = "Allow all IPv6 egress traffic"
    }
  }
}

resource "oci_core_subnet" "diagnostic_subnet" {
  compartment_id    = var.compartment_id
  vcn_id            = oci_core_vcn.diagnostic_vcn.id
  cidr_block        = var.diagnostic_subnet_cidr
  display_name      = "${var.prefix}-diag-subnet"
  dns_label         = "diagnosticsub"
  route_table_id    = oci_core_route_table.diagnostic_rt.id
  security_list_ids = [oci_core_security_list.diagnostic_sl.id]
  ipv6cidr_block = length(oci_core_vcn.diagnostic_vcn.ipv6cidr_blocks) > 0 ? cidrsubnet(oci_core_vcn.diagnostic_vcn.ipv6cidr_blocks[0], 8, 0) : null
}

resource "oci_core_network_security_group" "diagnostic_nsg" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.diagnostic_vcn.id
  display_name   = "${var.prefix}-diag-nsg"
}

# Inside Network
resource "oci_core_vcn" "inside_vcn" {
  compartment_id = var.compartment_id
  cidr_blocks    = [var.inside_vcn_cidr]
  display_name   = "${var.prefix}-inside-vcn"
  dns_label      = "insidevcn"
  is_ipv6enabled = true

  lifecycle {
    ignore_changes = [defined_tags]
  }

  freeform_tags = {
    Environment = "test"
    Purpose     = "inside"
    Prefix      = var.prefix
  }
}

resource "oci_core_internet_gateway" "inside_igw" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.inside_vcn.id
  display_name   = "${var.prefix}-inside-vcn-igw"
  enabled        = true
}

resource "oci_core_route_table" "inside_rt" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.inside_vcn.id
  display_name   = "${var.prefix}-inside-vcn-rt"

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.inside_igw.id
    description       = "Default IPv4 route"
  }

  dynamic "route_rules" {
    for_each = [1]
    content {
      destination       = "::/0"
      destination_type  = "CIDR_BLOCK"
      network_entity_id = oci_core_internet_gateway.inside_igw.id
      description       = "Default IPv6 route"
    }
  }
}

resource "oci_core_security_list" "inside_sl" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.inside_vcn.id
  display_name   = "${var.prefix}-inside-vcn-sl"

  # Cisco NAT Pool IPv4 ingress rules
  dynamic "ingress_security_rules" {
    for_each = var.cisco_nat_pool_ipv4
    content {
      protocol    = "all"
      source      = ingress_security_rules.value
      source_type = "CIDR_BLOCK"
      description = "Allow traffic from Cisco NAT Pool IPv4: ${ingress_security_rules.value}"
    }
  }

  # Cisco NAT Pool IPv6 ingress rules
  dynamic "ingress_security_rules" {
    for_each = var.cisco_nat_pool_ipv6
    content {
      protocol    = "all"
      source      = ingress_security_rules.value
      source_type = "CIDR_BLOCK"
      description = "Allow traffic from Cisco NAT Pool IPv6: ${ingress_security_rules.value}"
    }
  }

  egress_security_rules {
    protocol         = "all"
    destination      = "0.0.0.0/0"
    destination_type = "CIDR_BLOCK"
    description      = "Allow all IPv4 egress traffic"
  }

  dynamic "egress_security_rules" {
    for_each = [1]
    content {
      protocol         = "all"
      destination      = "::/0"
      destination_type = "CIDR_BLOCK"
      description      = "Allow all IPv6 egress traffic"
    }
  }
}

# Inside Subnet (for FTDv/ASAv inside interface and endpoint1 data interface)
resource "oci_core_subnet" "inside_subnet" {
  compartment_id    = var.compartment_id
  vcn_id            = oci_core_vcn.inside_vcn.id
  cidr_block        = var.inside_subnet_cidr
  display_name      = "${var.prefix}-inside-subnet"
  dns_label         = "insidesub"
  route_table_id    = oci_core_route_table.inside_rt.id
  security_list_ids = [oci_core_security_list.inside_sl.id]
  ipv6cidr_block    = length(oci_core_vcn.inside_vcn.ipv6cidr_blocks) > 0 ? cidrsubnet(oci_core_vcn.inside_vcn.ipv6cidr_blocks[0], 8, 0) : null
}

resource "oci_core_network_security_group" "inside_nsg" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.inside_vcn.id
  display_name   = "${var.prefix}-inside-nsg"
}

# Outside Network
resource "oci_core_vcn" "outside_vcn" {
  compartment_id = var.compartment_id
  cidr_blocks    = [var.outside_vcn_cidr]
  display_name   = "${var.prefix}-outside-vcn"
  dns_label      = "outsidevcn"
  is_ipv6enabled = true

  lifecycle {
    ignore_changes = [defined_tags]
  }

  freeform_tags = {
    Environment = "test"
    Purpose     = "outside"
    Prefix      = var.prefix
  }
}

resource "oci_core_internet_gateway" "outside_igw" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.outside_vcn.id
  display_name   = "${var.prefix}-outside-vcn-igw"
  enabled        = true
}

resource "oci_core_route_table" "outside_rt" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.outside_vcn.id
  display_name   = "${var.prefix}-outside-vcn-rt"

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.outside_igw.id
    description       = "Default IPv4 route"
  }

  dynamic "route_rules" {
    for_each = [1]
    content {
      destination       = "::/0"
      destination_type  = "CIDR_BLOCK"
      network_entity_id = oci_core_internet_gateway.outside_igw.id
      description       = "Default IPv6 route"
    }
  }
}

resource "oci_core_security_list" "outside_sl" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.outside_vcn.id
  display_name   = "${var.prefix}-outside-vcn-sl"

  # Cisco NAT Pool IPv4 ingress rules
  dynamic "ingress_security_rules" {
    for_each = var.cisco_nat_pool_ipv4
    content {
      protocol    = "all"
      source      = ingress_security_rules.value
      source_type = "CIDR_BLOCK"
      description = "Allow traffic from Cisco NAT Pool IPv4: ${ingress_security_rules.value}"
    }
  }

  # Cisco NAT Pool IPv6 ingress rules
  dynamic "ingress_security_rules" {
    for_each = var.cisco_nat_pool_ipv6
    content {
      protocol    = "all"
      source      = ingress_security_rules.value
      source_type = "CIDR_BLOCK"
      description = "Allow traffic from Cisco NAT Pool IPv6: ${ingress_security_rules.value}"
    }
  }

  egress_security_rules {
    protocol         = "all"
    destination      = "0.0.0.0/0"
    destination_type = "CIDR_BLOCK"
    description      = "Allow all IPv4 egress traffic"
  }

  dynamic "egress_security_rules" {
    for_each = [1]
    content {
      protocol         = "all"
      destination      = "::/0"
      destination_type = "CIDR_BLOCK"
      description      = "Allow all IPv6 egress traffic"
    }
  }
}

# Outside Subnet (for FTDv/ASAv outside interface and endpoint2 data interface)
resource "oci_core_subnet" "outside_subnet" {
  compartment_id    = var.compartment_id
  vcn_id            = oci_core_vcn.outside_vcn.id
  cidr_block        = var.outside_subnet_cidr
  display_name      = "${var.prefix}-outside-subnet"
  dns_label         = "outsidesub"
  route_table_id    = oci_core_route_table.outside_rt.id
  security_list_ids = [oci_core_security_list.outside_sl.id]
  ipv6cidr_block    = length(oci_core_vcn.outside_vcn.ipv6cidr_blocks) > 0 ? cidrsubnet(oci_core_vcn.outside_vcn.ipv6cidr_blocks[0], 8, 0) : null
}

resource "oci_core_network_security_group" "outside_nsg" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.outside_vcn.id
  display_name   = "${var.prefix}-outside-nsg"
}

# Function Network (for autoscale deployment)
resource "oci_core_vcn" "function_vcn" {
  count          = var.create_function_subnet ? 1 : 0
  compartment_id = var.compartment_id
  cidr_blocks    = [var.function_vcn_cidr]
  display_name   = "${var.prefix}-function-vcn"
  dns_label      = "functionvcn"
  is_ipv6enabled = true

  lifecycle {
    ignore_changes = [defined_tags]
  }

  freeform_tags = {
    Environment = "test"
    Purpose     = "function"
    Prefix      = var.prefix
  }
}

resource "oci_core_internet_gateway" "function_igw" {
  count          = var.create_function_subnet ? 1 : 0
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.function_vcn[0].id
  display_name   = "${var.prefix}-function-vcn-igw"
  enabled        = true
}

# NAT Gateway for Function VCN (allows functions to access FTDv/FMCv via management network)
resource "oci_core_nat_gateway" "function_nat_gw" {
  count          = var.create_function_subnet ? 1 : 0
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.function_vcn[0].id
  display_name   = "${var.prefix}-function-nat-gw"
  block_traffic  = false
}

resource "oci_core_route_table" "function_rt" {
  count          = var.create_function_subnet ? 1 : 0
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.function_vcn[0].id
  display_name   = "${var.prefix}-function-vcn-rt"

  # IPv4 traffic routes through NAT Gateway (for private subnet access to FTDv/FMCv)
  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_nat_gateway.function_nat_gw[0].id
    description       = "Default IPv4 route via NAT Gateway"
  }

  # IPv6 traffic still routes through Internet Gateway
  dynamic "route_rules" {
    for_each = [1]
    content {
      destination       = "::/0"
      destination_type  = "CIDR_BLOCK"
      network_entity_id = oci_core_internet_gateway.function_igw[0].id
      description       = "Default IPv6 route via Internet Gateway"
    }
  }
}

resource "oci_core_security_list" "function_sl" {
  count          = var.create_function_subnet ? 1 : 0
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.function_vcn[0].id
  display_name   = "${var.prefix}-function-vcn-sl"

  # Cisco NAT Pool IPv4 ingress rules
  dynamic "ingress_security_rules" {
    for_each = var.cisco_nat_pool_ipv4
    content {
      protocol    = "all"
      source      = ingress_security_rules.value
      source_type = "CIDR_BLOCK"
      description = "Allow traffic from Cisco NAT Pool IPv4: ${ingress_security_rules.value}"
    }
  }

  # Cisco NAT Pool IPv6 ingress rules
  dynamic "ingress_security_rules" {
    for_each = var.cisco_nat_pool_ipv6
    content {
      protocol    = "all"
      source      = ingress_security_rules.value
      source_type = "CIDR_BLOCK"
      description = "Allow traffic from Cisco NAT Pool IPv6: ${ingress_security_rules.value}"
    }
  }

  egress_security_rules {
    protocol         = "all"
    destination      = "0.0.0.0/0"
    destination_type = "CIDR_BLOCK"
    description      = "Allow all IPv4 egress traffic"
  }

  dynamic "egress_security_rules" {
    for_each = [1]
    content {
      protocol         = "all"
      destination      = "::/0"
      destination_type = "CIDR_BLOCK"
      description      = "Allow all IPv6 egress traffic"
    }
  }
}

resource "oci_core_subnet" "function_subnet" {
  count             = var.create_function_subnet ? 1 : 0
  compartment_id    = var.compartment_id
  vcn_id            = oci_core_vcn.function_vcn[0].id
  cidr_block        = var.function_subnet_cidr
  display_name      = "${var.prefix}-function-subnet"
  dns_label         = "functionsub"
  route_table_id    = oci_core_route_table.function_rt[0].id
  security_list_ids = [oci_core_security_list.function_sl[0].id]
  ipv6cidr_block    = length(oci_core_vcn.function_vcn[0].ipv6cidr_blocks) > 0 ? cidrsubnet(oci_core_vcn.function_vcn[0].ipv6cidr_blocks[0], 8, 0) : null
}

resource "oci_core_network_security_group" "function_nsg" {
  count          = var.create_function_subnet ? 1 : 0
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.function_vcn[0].id
  display_name   = "${var.prefix}-function-nsg"
}

# NSG Rule to allow Function NAT Gateway IP to access Management NSG (for FTDv/FMCv access)
resource "oci_core_network_security_group_security_rule" "mgmt_allow_function_nat_gw" {
  count                     = var.create_function_subnet ? 1 : 0
  network_security_group_id = oci_core_network_security_group.management_nsg.id
  direction                 = "INGRESS"
  protocol                  = "all"
  source_type               = "CIDR_BLOCK"
  source                    = "${oci_core_nat_gateway.function_nat_gw[0].public_ip_address}/32"
  description               = "Allow traffic from Function NAT Gateway for autoscale functions to access FTDv/FMCv"
}

# =============================================================================
# OUTPUTS
# =============================================================================

# Management Network Outputs
output "management" {
  description = "Management network resource details"
  value = {
    vcn_id                  = oci_core_vcn.management_vcn.id
    vcn_name               = oci_core_vcn.management_vcn.display_name
    vcn_cidr               = oci_core_vcn.management_vcn.cidr_blocks[0]
    vcn_ipv6_cidr          = length(oci_core_vcn.management_vcn.ipv6cidr_blocks) > 0 ? oci_core_vcn.management_vcn.ipv6cidr_blocks[0] : null
    subnet_id              = oci_core_subnet.management_subnet.id
    subnet_name            = oci_core_subnet.management_subnet.display_name
    subnet_cidr            = oci_core_subnet.management_subnet.cidr_block
    subnet_ipv6_cidr       = length(oci_core_subnet.management_subnet.ipv6cidr_blocks) > 0 ? oci_core_subnet.management_subnet.ipv6cidr_blocks[0] : null
    nsg_id                 = oci_core_network_security_group.management_nsg.id
    nsg_name               = oci_core_network_security_group.management_nsg.display_name
    internet_gateway_id    = oci_core_internet_gateway.management_igw.id
    internet_gateway_name  = oci_core_internet_gateway.management_igw.display_name
    route_table_id         = oci_core_route_table.management_rt.id
    route_table_name       = oci_core_route_table.management_rt.display_name
    security_list_id       = oci_core_security_list.management_sl.id
    security_list_name     = oci_core_security_list.management_sl.display_name
    # Add gateway IPs
    subnet_gateway_ip     = cidrhost(oci_core_subnet.management_subnet.cidr_block, 1)
    subnet_gateway_ipv6   = length(oci_core_subnet.management_subnet.ipv6cidr_blocks) > 0 ? cidrhost(oci_core_subnet.management_subnet.ipv6cidr_blocks[0], 1) : null
  }
}

output "diagnostic" {
  description = "Diagnostic network resource details"
  value = {
    vcn_id                  = oci_core_vcn.diagnostic_vcn.id
    vcn_name               = oci_core_vcn.diagnostic_vcn.display_name
    vcn_cidr               = oci_core_vcn.diagnostic_vcn.cidr_blocks[0]
    vcn_ipv6_cidr          = length(oci_core_vcn.diagnostic_vcn.ipv6cidr_blocks) > 0 ? oci_core_vcn.diagnostic_vcn.ipv6cidr_blocks[0] : null
    subnet_id              = oci_core_subnet.diagnostic_subnet.id
    subnet_name            = oci_core_subnet.diagnostic_subnet.display_name
    subnet_cidr            = oci_core_subnet.diagnostic_subnet.cidr_block
    subnet_ipv6_cidr       = length(oci_core_subnet.diagnostic_subnet.ipv6cidr_blocks) > 0 ? oci_core_subnet.diagnostic_subnet.ipv6cidr_blocks[0] : null
    nsg_id                 = oci_core_network_security_group.diagnostic_nsg.id
    nsg_name               = oci_core_network_security_group.diagnostic_nsg.display_name
    internet_gateway_id    = oci_core_internet_gateway.diagnostic_igw.id
    internet_gateway_name  = oci_core_internet_gateway.diagnostic_igw.display_name
    route_table_id         = oci_core_route_table.diagnostic_rt.id
    route_table_name       = oci_core_route_table.diagnostic_rt.display_name
    security_list_id       = oci_core_security_list.diagnostic_sl.id
    security_list_name     = oci_core_security_list.diagnostic_sl.display_name
    # Add gateway IPs
    subnet_gateway_ip     = cidrhost(oci_core_subnet.diagnostic_subnet.cidr_block, 1)
    subnet_gateway_ipv6   = length(oci_core_subnet.diagnostic_subnet.ipv6cidr_blocks) > 0 ? cidrhost(oci_core_subnet.diagnostic_subnet.ipv6cidr_blocks[0], 1) : null
  }
}

output "inside" {
  description = "Inside network resource details"
  value = {
    vcn_id                  = oci_core_vcn.inside_vcn.id
    vcn_name               = oci_core_vcn.inside_vcn.display_name
    vcn_cidr               = oci_core_vcn.inside_vcn.cidr_blocks[0]
    vcn_ipv6_cidr          = length(oci_core_vcn.inside_vcn.ipv6cidr_blocks) > 0 ? oci_core_vcn.inside_vcn.ipv6cidr_blocks[0] : null
    subnet_id              = oci_core_subnet.inside_subnet.id
    subnet_name            = oci_core_subnet.inside_subnet.display_name
    subnet_cidr            = oci_core_subnet.inside_subnet.cidr_block
    subnet_ipv6_cidr       = length(oci_core_subnet.inside_subnet.ipv6cidr_blocks) > 0 ? oci_core_subnet.inside_subnet.ipv6cidr_blocks[0] : null
    nsg_id                 = oci_core_network_security_group.inside_nsg.id
    nsg_name               = oci_core_network_security_group.inside_nsg.display_name
    internet_gateway_id    = oci_core_internet_gateway.inside_igw.id
    internet_gateway_name  = oci_core_internet_gateway.inside_igw.display_name
    route_table_id         = oci_core_route_table.inside_rt.id
    route_table_name       = oci_core_route_table.inside_rt.display_name
    security_list_id       = oci_core_security_list.inside_sl.id
    security_list_name     = oci_core_security_list.inside_sl.display_name
    subnet_gateway_ip      = cidrhost(oci_core_subnet.inside_subnet.cidr_block, 1)
    subnet_gateway_ipv6    = length(oci_core_subnet.inside_subnet.ipv6cidr_blocks) > 0 ? cidrhost(oci_core_subnet.inside_subnet.ipv6cidr_blocks[0], 1) : null
  }
}

output "outside" {
  description = "Outside network resource details"
  value = {
    vcn_id                  = oci_core_vcn.outside_vcn.id
    vcn_name               = oci_core_vcn.outside_vcn.display_name
    vcn_cidr               = oci_core_vcn.outside_vcn.cidr_blocks[0]
    vcn_ipv6_cidr          = length(oci_core_vcn.outside_vcn.ipv6cidr_blocks) > 0 ? oci_core_vcn.outside_vcn.ipv6cidr_blocks[0] : null
    subnet_id              = oci_core_subnet.outside_subnet.id
    subnet_name            = oci_core_subnet.outside_subnet.display_name
    subnet_cidr            = oci_core_subnet.outside_subnet.cidr_block
    subnet_ipv6_cidr       = length(oci_core_subnet.outside_subnet.ipv6cidr_blocks) > 0 ? oci_core_subnet.outside_subnet.ipv6cidr_blocks[0] : null
    nsg_id                 = oci_core_network_security_group.outside_nsg.id
    nsg_name               = oci_core_network_security_group.outside_nsg.display_name
    internet_gateway_id    = oci_core_internet_gateway.outside_igw.id
    internet_gateway_name  = oci_core_internet_gateway.outside_igw.display_name
    route_table_id         = oci_core_route_table.outside_rt.id
    route_table_name       = oci_core_route_table.outside_rt.display_name
    security_list_id       = oci_core_security_list.outside_sl.id
    security_list_name     = oci_core_security_list.outside_sl.display_name
    subnet_gateway_ip      = cidrhost(oci_core_subnet.outside_subnet.cidr_block, 1)
    subnet_gateway_ipv6    = length(oci_core_subnet.outside_subnet.ipv6cidr_blocks) > 0 ? cidrhost(oci_core_subnet.outside_subnet.ipv6cidr_blocks[0], 1) : null
  }
}

output "function" {
  description = "Function network resource details (for autoscale deployment)"
  value = var.create_function_subnet ? {
    vcn_id                  = oci_core_vcn.function_vcn[0].id
    vcn_name               = oci_core_vcn.function_vcn[0].display_name
    vcn_cidr               = oci_core_vcn.function_vcn[0].cidr_blocks[0]
    vcn_ipv6_cidr          = length(oci_core_vcn.function_vcn[0].ipv6cidr_blocks) > 0 ? oci_core_vcn.function_vcn[0].ipv6cidr_blocks[0] : null
    subnet_id              = oci_core_subnet.function_subnet[0].id
    subnet_name            = oci_core_subnet.function_subnet[0].display_name
    subnet_cidr            = oci_core_subnet.function_subnet[0].cidr_block
    subnet_ipv6_cidr       = length(oci_core_subnet.function_subnet[0].ipv6cidr_blocks) > 0 ? oci_core_subnet.function_subnet[0].ipv6cidr_blocks[0] : null
    nsg_id                 = oci_core_network_security_group.function_nsg[0].id
    nsg_name               = oci_core_network_security_group.function_nsg[0].display_name
    internet_gateway_id    = oci_core_internet_gateway.function_igw[0].id
    internet_gateway_name  = oci_core_internet_gateway.function_igw[0].display_name
    nat_gateway_id         = oci_core_nat_gateway.function_nat_gw[0].id
    nat_gateway_name       = oci_core_nat_gateway.function_nat_gw[0].display_name
    nat_gateway_public_ip  = oci_core_nat_gateway.function_nat_gw[0].public_ip_address
    route_table_id         = oci_core_route_table.function_rt[0].id
    route_table_name       = oci_core_route_table.function_rt[0].display_name
    security_list_id       = oci_core_security_list.function_sl[0].id
    security_list_name     = oci_core_security_list.function_sl[0].display_name
    subnet_gateway_ip      = cidrhost(oci_core_subnet.function_subnet[0].cidr_block, 1)
    subnet_gateway_ipv6    = length(oci_core_subnet.function_subnet[0].ipv6cidr_blocks) > 0 ? cidrhost(oci_core_subnet.function_subnet[0].ipv6cidr_blocks[0], 1) : null
  } : null
}
