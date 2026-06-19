# OCI Provider Configuration
tenancy_ocid    = "__tenancy_ocid__"
region          = "__region__"

# Network Configuration
compartment_id  = "__compartment_id__"
prefix          = "__prefix__"

# Network CIDR Configuration (dynamically generated from base CIDR)
management_vcn_cidr    = "__management_vcn_cidr__"
management_subnet_cidr = "__management_subnet_cidr__"
diagnostic_vcn_cidr    = "__diagnostic_vcn_cidr__"
diagnostic_subnet_cidr = "__diagnostic_subnet_cidr__"
inside_vcn_cidr        = "__inside_vcn_cidr__"
inside_subnet_cidr     = "__inside_subnet_cidr__"
outside_vcn_cidr       = "__outside_vcn_cidr__"
outside_subnet_cidr    = "__outside_subnet_cidr__"

# Function Network Configuration (for autoscale deployment)
create_function_subnet = "__create_function_subnet__"
function_vcn_cidr      = "__function_vcn_cidr__"
function_subnet_cidr   = "__function_subnet_cidr__"

# Cisco NAT Pool IP ranges for security rules (sourced from constants)
cisco_nat_pool_ipv4 = "__cisco_nat_pool_ipv4__"

cisco_nat_pool_ipv6 = "__cisco_nat_pool_ipv6__"
