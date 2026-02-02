# Project Configuration
resource_name_prefix        = "resource-name-prefix"    # Resource prefix (e.g. random)
region                      = "region"                  # GCP region (e.g. us-central1)
project_id                  = "project-id"              # GCP project ID (e.g. asav)

# Network Configuration
mgmt_ip_cidr_range          = "10.114.0.0/27"           # Management subnet (e.g. 10.114.0.0/27)
vpc_connector_ip_cidr_range = "10.114.50.0/28"          # VPC connector /28 (e.g. 10.114.50.0/28)
inside_ip_cidr_range        = "10.114.1.0/27"           # Inside subnet (e.g. 10.114.1.0/27)
outside_ip_cidr_range       = "10.114.2.0/27"           # Outside subnet (e.g. 10.114.2.0/27)
ccl_ip_cidr_range           = "10.114.3.0/27"           # CCL subnet (e.g. 10.114.3.0/27)