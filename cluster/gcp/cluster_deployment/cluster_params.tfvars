# --------------------
# Project Configuration
# --------------------
project_id                  = "<project-id>"                           # The GCP project ID, e.g., "my-gcp-project"
resource_name_prefix        = "<resource_name_prefix>"                 # Prefix for resource names, e.g., "democluster"
type_of_deployment          = "east_west"                              # Type of deployment, e.g., "east_west" or "north_south"  
region                      = "region"                                 # GCP region, e.g., "us-central1"
zone1                       = "a"                                      # Deployment zone 1, e.g., "a"
zone2                       = "b"                                      # Deployment zone 2, e.g., "b"
zone3                       = "c"                                      # Deployment zone 3, e.g., "c"

# --------------------
# VM Configuration
# --------------------
machine_type                = "<machine-type>"                         # VM instance type, e.g., "n1-standard-4"
source_image_url            = "<source-image-url>"                     # URL of the source image, e.g., "projects/my-project/global/images/my-image"
assign_public_ip_to_mgmt    = false                                    # Whether to assign a public IP to the management interface (true/false)
public_key                  = "<public-key>"                           # SSH public key for authentication, e.g., "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ..."
service_account_mail_id     = "<service-account-mail>"                 # Service account email, e.g., "my-service-account@my-project.iam.gserviceaccount.com"
asav_password_secret_name   = "<asav-password-secret-name>"            # Secret name for ASAv password, e.g., "asav_password_secret" in GCP Secret Manager
asav_en_password_secret_name= "<asav-en-password-secret-name>"         # Secret name for ASAv encrypted password, e.g., "asav_en_password_secret" in GCP Secret Manager

# --------------------
# VPC Configuration
# --------------------
outside_vpc_name            = "<resource_name_prefix>-outside-vpc"     # Name of the outside VPC, e.g., "my-resources-outside-vpc"
inside_vpc_name             = "<resource_name_prefix>-inside-vpc"      # Name of the inside VPC, e.g., "my-resources-inside-vpc"
mgmt_vpc_name               = "<resource_name_prefix>-mgmt-vpc"        # Name of the management VPC, e.g., "my-resources-mgmt-vpc"
ccl_vpc_name                = "<resource_name_prefix>-ccl-vpc"         # Name of the clustering VPC, e.g., "my-resources-ccl-vpc"
outside_subnet_name         = "<resource_name_prefix>-outside-subnet"  # Name of the outside subnet, e.g., "my-resources-outside-subnet"
inside_subnet_name          = "<resource_name_prefix>-inside-subnet"   # Name of the inside subnet, e.g., "my-resources-inside-subnet"
mgmt_subnet_name            = "<resource_name_prefix>-mgmt-subnet"     # Name of the management subnet, e.g., "my-resources-mgmt-subnet"
ccl_subnet_name             = "<resource_name_prefix>-ccl-subnet"      # Name of the clustering subnet, e.g., "my-resources-ccl-subnet"
# VPC Connector
vpc_connector_name          = "<resource_name_prefix>-connector"       # Name of the VPC connector (), e.g., "my-vpc-connector"

# --------------------
# Firewall Rules
# --------------------
inside_firewall_rule_name   = "<resource_name_prefix>-in-firewall-rule"       # Name of the inside firewall rule, e.g., "allow-inside-traffic"
outside_firewall_rule_name  = "<resource_name_prefix>-out-firewall-rule"      # Name of the outside firewall rule, e.g., "allow-outside-traffic"
mgmt_firewall_rule_name     = "<resource_name_prefix>-mgmt-firewall-rule"     # Name of the management firewall rule, e.g., "allow-management-traffic"
ccl_firewall_rule_name      = "<resource_name_prefix>-mgmt-firewall-rule"     # Name of the clustering firewall rule, e.g., "allow-clustering-traffic"

# --------------------
# Cluster
# --------------------
cluster_grp_name            = "cluster-group-name"                     # Name of the cluster group, e.g., "my-cluster-group"
ccl_subnet_firstIp          = ""                                       # First IP address in the clustering subnet, e.g., "10.0.0.1"
ccl_subnet_lastIp           = ""                                       # Last IP address in the clustering subnet, e.g., "10.0.0.254"

# --------------------
# Autoscaling Configuration
# --------------------
auto_scaling                = false                                    # Enable or disable autoscaling (true/false), If disabled, min_asa_count will be used as target count.
cpu_utilization_target      = 0.2                                      # Target CPU utilization for autoscaling, e.g., 0.2 (20%)
min_asa_count               = 1                                        # Minimum number of instances in the autoscaling group, e.g., 1
max_asa_count               = 2                                        # Maximum number of instances in the autoscaling group, e.g., 2

# --------------------
# External Load Balancer Configuration
# --------------------
elb_frontend_protocol       = "TCP"                                    # Frontend protocol for the external load balancer, e.g., "TCP"
elb_backend_protocol        = "TCP"                                    # Backend protocol for the external load balancer, e.g., "TCP"
elb_front_end_ports         = "[80, 443]" or "all"                     # Frontend ports for the external load balancer, e.g., "[80, 443]" or "all"

# ELB Health Check
elb_health_check_port       = 80                                       # Health check port for the external load balancer, e.g., 80
elb_check_interval_sec      = 10         							   # Health check interval for the external load balancer in seconds, e.g., 10	
elb_timeout_sec             = 5                                        # Timeout for the external load balancer in seconds, e.g., 5
elb_unhealthy_threshold     = 2                                        # Unhealthy threshold for the external load balancer, e.g., 2

# --------------------
# Internal Load Balancer Configuration
# --------------------
ilb_frontend_protocol       = "TCP"                                    # Protocol for the internal load balancer, e.g., "TCP"
ilb_backend_protocol        = "TCP"                                    # Name of the internal load balancer protocol, e.g., "TCP"

# ILB Health Check
ilb_health_check_port       = 80                                       # Port for the internal load balancer, e.g., 80
ilb_check_interval_sec      = 10                                       # Health check interval for the internal load balancer in seconds, e.g., 10
ilb_timeout_sec             = 5                                        # Timeout for the internal load balancer in seconds, e.g., 5
ilb_unhealthy_threshold     = 3                                        # Unhealthy threshold for the internal load balancer, e.g., 3

# --------------------
# Licensing
# --------------------
license_throughput          = "10G"                                    # Throughput for the license, e.g., "10G"
license_id_token            = "license-id-token"                       # License ID token, e.g., "my-license-id-token"
