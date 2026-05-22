# Project Configuration
project_id           = "project-id"           # e.g., "asav"
resource_name_prefix = "resource-name-prefix" # e.g., "random-terraform-asavautoscale"
region               = "region"               # e.g., "us-central1"

# Machine Configuration
machine_type     = "machine-type"     # e.g., "n1-standard-4"
source_image_url = "source-image-url" # e.g., "projects/asav-4krn/global/images/asav-gcp-99-76-1-11"
assign_public_ip_to_mgmt    = true    # Whether to assign a public IP to the management interface (true/false)
enable_secure_boot          = false   # Supported from ASAv 9.24+. Set true to enable Secure Boot


# Security and Authentication
public_key              = "public-key"           # e.g., "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCNQqBL9vjTT01O1ATo8Qm0DuhWRC..."
service_account_mail_id = "service-account-mail" # e.g., "random@asav.iam.gserviceaccount.com"

# Autoscaling Configuration
cpu_utilization_target = 0.2
cool_down_period_sec   = 30
min_asa_count           = 1
max_asa_count           = 2
zone                   = "b" # Deployment zone (comma separated alphabets, 3 at most), e.g. "b,c" Valid zones : https://cloud.google.com/compute/docs/regions-zones

# External Load Balancer Configuration
elb_health_check_port   = 80
elb_port_range          = "80-80"
elb_port_name           = "tcp"
elb_protocol            = "TCP"
elb_protocol_name       = "TCP"
elb_ip_protocol         = "TCP"
elb_timeout_sec         = 5
elb_unhealthy_threshold = 2

# Internal Load Balancer Configuration
ilb_protocol             = "TCP"
ilb_protocol_name        = "TCP"
ilb_health_check_port    = 80
ilb_check_interval_sec   = 10
ilb_timeout_sec          = 5
ilb_unhealthy_threshold  = 3
ilb_draining_timeout_sec = 60

# VPC Configuration
outside_vpc_name   = "<resource_name_prefix>-outside-vpc"   # e.g., "random-terraform-asavautoscale-outside-vpc"
outside_subnet_name = "<resource_name_prefix>-outside-subnet" # e.g., "random-terraform-asavautoscale-outside-subnet"
inside_vpc_name    = "<resource_name_prefix>-inside-vpc"    # e.g., "random-terraform-asavautoscale-inside-vpc"
inside_subnet_name  = "<resource_name_prefix>-inside-subnet"  # e.g., "random-terraform-asavautoscale-inside-subnet"
mgmt_vpc_name      = "<resource_name_prefix>-mgmt-vpc"      # e.g., "random-terraform-asavautoscale-mgmt-vpc"
mgmt_subnet_name    = "<resource_name_prefix>-mgmt-subnet"    # e.g., "random-terraform-asavautoscale-mgmt-subnet"

# Target Configuration
appserver_ip = "appserver-ip" # e.g., "10.114.1.1"

# Firewall Rules
inside_firewall_rule_name       = "allow-asa-i"  # e.g., "allow-asa-i"
outside_firewall_rule_name      = "allow-asa-o"  # e.g., "allow-asa-o"
mgmt_firewall_rule_name         = "allow-asa-m"  # e.g., "allow-asa-m"
health_check_firewall_rule_name = "allow-asa-hc" # e.g., "allow-asa-hc"

# VPC Connector
vpc_connector_name = "vpc-connector-name" # e.g., "randomasav-vpc-connector"

# Licensing
license_id_token = "license-id-token"        # e.g., "HKASNDK"
license_throughput = "10G"                   # Throughput for the license, e.g., "10G"
