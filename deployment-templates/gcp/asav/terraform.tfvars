project_id           = "asavgcp-poc-4krn"
region               = "us-central1"
zone                 = "us-central1-a"
resource_name_prefix = "cim-tf"

image              = "projects/cisco-public/global/images/cisco-asav-9-23-1"
machine_type       = "n1-standard-4"
enable_secure_boot = false

mgmt_vpc_name       = "cim-tf-mgmt-vpc"
mgmt_subnet_name    = "cim-tf-mgmt-subnet"
inside_vpc_name     = "cim-tf-inside-vpc"
inside_subnet_name  = "cim-tf-inside-subnet"
outside_vpc_name    = "cim-tf-outside-vpc"
outside_subnet_name = "cim-tf-outside-subnet"
day0_config         = " "
