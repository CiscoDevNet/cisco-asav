# ASAv OpenStack heat template 

The required heat template files to deploy ASAv on OpenStack:


| Files | Description |
| ------ | ------ |
| env.yaml | Environment file |
| deploy_os_infra.yaml | OpenStack Infrastructure file |
| deploy_asav.yaml| ASAv template file |


##	1. Environment file
Defines the environment variables to be used to create OpenStack infrastructure.

### 1.1 Variables
The below table describes parameters that the env.yaml file expects the user to provide for the ASAv stack to be created successfully.

| Variables | Description |
| ------ | ------ |
| glance_asav_image_name | Name of the ASAv QCOW2 image uploaded to OpenStack using openstack image create command. |
| mgmt_net_cidr| Management network CIDR (Example : 40.40.1.0/24) |
| inside_net_cidr | Inside network CIDR (Example : 40.40.3.0/24) |
| outside_net_cidr | Outside network CIDR (Example : 40.40.4.0/24) |
| provider_phys_net_name | Name of the neutron provider network mapping (Example : extnet) More info @ https://docs.openstack.org/openstack-ansible-os_neutron/rocky/app-openvswitch.html |
| provider_net_type | Neutron provider network type (Example : flat) More Info @ https://docs.openstack.org/openstack-ansible-os_neutron/rocky/app-openvswitch.html |
| ext_net_cidr| Provider network CIDR  (Example : 10.10.4.224/27) |
| ext_net_gw_ip | Provider network gateway (Example : 10.10.4.225)|
| ext_net_start_ip | Provider network start IP (Example : 10.10.4.235) |
| ext_net_end_ip| Provider network end IP (Example : 10.10.4.245) |

## 2. OpenStack Infrastructure file
Template file to create an OpenStack infrasturcure such as Networks, Subnets, Router and Router associated subnets.

###	2.1 Parameters
The table below describes parameters that the deploy_os_infra.yaml template file uses to create the resources and provides the default value, if applicable.

| Variables | Description |
| ------ | ------ |
| mgmt_net_cidr | Management network CIDR  (Example : 40.40.1.0/24) |
| mgmt_net_name| Name for the management network |
| mgmt_subnet_name | Name for the management subnet |
| diag_net_cidr | Diagnostic network CIDR  (Example : 40.40.2.0/24) |
| diag_net_name| Name for the diagnostic network |
| diag_subnet_name | Name for the diagnostic subnet |
| inside_net_cidr | Inside network CIDR (Example : 40.40.3.0/24) |
| inside_net_name | Name for the inside network |
| inside_subnet_name | Name for the inside subnet |
| outside_net_cidr | Inside network CIDR (Example : 40.40.4.0/24) |
| outside_net_name | Name for the outside network |
| outside_subnet_name | Name for the outside subnet |
| provider_phys_net_name | Neutron provider network mapping (Example : extnet) |
| provider_net_type | Neutron provider network type (Example : flat) |
| ext_net_cidr | Provider network CIDR (Example : 10.10.4.224/27) |
| ext_net_name | Name for the external network. |
| ext_subnet_name | Name for the external subnet. |
| ext_net_gw_ip | Provider network gateway (Example : 10.10.4.225) |
| ext_net_start_ip | Provider network start IP (Example : 10.10.4.235) |
| ext_net_end_ip | Provider network end IP (Example : 10.10.4.245) |

###	2.2 Resources
The table below describes resources that the deploy_os_infra.yaml template file creates and provides the default value, if applicable.

| Resources | Description |
| ------ | ------ |
| mgmt_net, diag_net, inside_net, outside_net, ext_net | Creates a Neutron network resources for mgmt, diag, inside, outside and external networks. |
| mgmt_subnet, diag_subnet, inside_subnet, outside_subnet, ext_subnet | Creates a Neutron subnet resources for mgmt, diag, inside, outside and external subnets. |
| os_router | Creates a Neutron router for all the above networks. |
| mgmt_router_patch, diag_router_patch, inside_router_patch, outside_router_patch | Attaches Neutron router with all the above subnets. |


## 3. ASAv template
Template file to create an ASAv instance and its flavor, security group, floating ip.

###	3.1 Parameters
The table below describes parameters that the deploy_asav.yaml template file uses to create the resources and provides the default value, if applicable.

| Variables | Description |
| ------ | ------ |
| asav_flavor_name | Name of the flavor used for deploying ASAv. Flavor with the provided name will be created. (flavor is an hardware configuration for a VM). |
| glance_asav_image_name | The name of ASAv QCOW2 image uploaded to OpenStack glance service using openstack image create command. |
| asav_secgroup_name | Name of the security group used for ASAv. Security group with the provided name will be created. (A security group defines the rules which specify the network access rules.) |
| mgmt_net_name | Name of management network mentioned in the default and  created during OpenStack infra deployment. |
| inside_net_name | Name of inside network mentioned in the default and  created during OpenStack infra deployment. |
| outside_net_name | 	Name of outside network mentioned in the default and  created during OpenStack infra deployment. |
| ext_net_name | Name of external network mentioned in the default and  created during OpenStack infra deployment. |
| mgmt_subnet_name | 	Name of management subnet mentioned in the default and  created during OpenStack infra deployment. |


###	3.2 Resources
The table below describes resources that the deploy_asav.yaml template file creates and provides the default value, if applicable.


| Resources | Description |
| ------ | ------ |
| asav_flav_res | Creates the asav flavor with the provided name in parameter section. Creates a flavor with ram: 16384, vcpus: 8, disk: 10. Modify the template if the flavor has to be created with different ram/cpu.  |
| asav_sec_grp | Creates the security group with the provided name. Creates a security group with security rules mentioned in rules properties of the template. Modify the template if the security group has to be created with different rules. |
| asav_float_ip | Creates the floating IP from the external network. Attaches the floating IP to the management port. |
| mgmt_port | Creates a management port from the mgmt_network for ASAv. Allocates an IP from mgmt_subnet. |
| in_port | Creates an inside port from the inside_network for ASAv. Allocates an IP from inside_subnet. |
| out_port | Creates an outside port from the outside_network for ASAv. Allocates an IP from outside_subnet. |
| asav | Creates an ASAv instance with resources,
| | 1. asav_flav_res |
| | 2. glance_asav_image_name |
| | 3. name : creates ASAv instance with the name   provided in this section |
| | 4.  network : mgmt_port, in_port, out_port |
| | 5. user_data :  day0-configuration has to be provided in this section. Modify the day0 configuration based on user’s choice. |

###	3.3 Output
The table below describes outputs that the deploy_asav.yaml template file provides on successful creation of stack.

| Resources | Description |
| ------ | ------ |
| server_ip |Provides ASAv management IP address |
| floating_ip | Provides ASAv floating IP address |


## Licensing Info
This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](../../LICENSE) file for details.

## Copyright
Copyright (c) 2021 Cisco Systems Inc and/or its affiliates.
