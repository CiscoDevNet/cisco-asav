# Azure ASAv HA deployment using VHD and ARM template

In addition to the Marketplace-based deployment, Cisco provides a compressed virtual hard disk (VHD) that you can upload to Azure and then use these ARM templates to deploy ASAv & ASAv HA in Azure.<br>
Using a Image and two JSON files (a Template file and a Parameter File), you can deploy and provision all the resources for the ASAv and ASAv HA in a single, coordinated operation.<br>

To deploy using a VHD image, you must upload the VHD image to your Azure storage account. Then, you can create an image using the uploaded disk image and use Azure Resource Manager template for deployment.<br>
Azure templates are JSON files that contain resource descriptions and parameter definitions.<br>

Use the instructions in the quick start guide for ASAv deployment.<br>
These instructions are for ASAv, ASAv HA deployment procedure is very similar.<br>

[ASAv deployment using VHD and ARM](https://www.cisco.com/c/en/us/td/docs/security/asa/asa917/asav/getting-started/asav-917-gsg/asav_azure.html#id_87923)<br>


## Deployment overview

1. Download the ASAv vhd image from Cisco Download Software download page.<br>
e.g. asav9-17-1.vhd.bz2<br>

2. Un-compress the *.bz2 & upload the VHD image to container in Azure storage account.<br>

3. Create a Image from the VHD and acquire the Resource ID of the newly created Image.<br>

4. Use the ARM template to deploy a Cisco Adaptive Security Virtual Appliance(ASAv) HA using the image.<br>

5. Update the parameters in the parameters template file(json) and use it to provide the parameters to the ARM template.<br>

6. Review and purchase the template to deploy Cisco Adaptive Security Virtual Appliance(ASAv) HA.<br>

7. Configure the Cisco Adaptive Security Virtual Appliance (ASAv) HA.<br>
Refer the ASAv HA documentation for this.<br>
[Azure ASAv HA configuration](https://www.cisco.com/c/en/us/td/docs/security/asa/asa917/configuration/general/asa-917-general-config/ha-failover-cloud.html)


## Parameters for the Azure ARM template:

### Pre-requisites:
1. Image ID (created using the downloaded vhd)
2. Virtual network with 4 subnets corresponding to management and 3 data subnets.

### Parameters:
1. **vmName-prefix**: The prefix for ASAv HA VMs name in Azure.<br>
e.g. cisco-asav-ha

2. **vmImageId**: The ID of the image used for deployment. Internally, Azure associates every resource with a Resource ID.<br>
e.g. /subscriptions/<subscription-id>/resourceGroups/images-rg/providers/Microsoft.Compute/images/asav-9-17-1

3. **adminUsername**: The username for logging into ASAv. This cannot be the reserved name ‘admin’.<br>
e.g. cisco

4. **adminPassword**: The admin password for ASAv VM.<br>
e.g. Password@2021<br>
ASAv Password constraints: <br>
  * Password must be 12 to 72 characters long (Azure Password constraint)
  * must have : 1 lowercase, 1 uppercase, 1 number & 1 special characters
  * must have no more than 2 repeating or sequential(ASCII) characters<br>

5. **vmStorageAccount-A**: Your Azure storage account for ASAv HA vm-A. You can use an existing storage account or create a new one. The storage account name must be between 3 and 24 characters, and can only contain lowercase letters and numbers.<br>
e.g. ciscoasavstorage1

6. **vmStorageAccount-B**: Your Azure storage account for ASAv HA vm-B. You can use an existing storage account or create a new one. The storage account name must be between 3 and 24 characters, and can only contain lowercase letters and numbers.<br>
e.g. ciscoasavstorage2

7. **virtualNetworkResourceGroup**: The name of the virtual network's Resource Group.<br>
e.g. asav-vnet-rg

8. **virtualNetworkName**: The name of the virtual network.<br>
e.g. asav-vnet

9. **mgmtSubnetName**: The management interface will attach to this subnet. This maps to Nic0, the first subnet. Note, this must match an existing subnet name if joining an existing network.<br>
e.g. mgmt

10. **mgmtSubnetIP-A**: The Management interface IP address for ASAv HA vm-A.<br>
e.g. 10.8.0.10

11. **mgmtSubnetIP-B**: The Management interface IP address for ASAv HA vm-B.<br>
e.g. 10.8.0.11

12. **data1SubnetName**: The data interface 1 will attach to this subnet. This maps to Nic1, the second subnet. Note, this must match an existing subnet name.<br>
e.g. data-subnet1

13. **data1SubnetIP-A**: The data interface 1: IP address for ASAv HA vm-A.<br>
e.g. 10.8.1.10

14. **data1SubnetIP-B**: The data interface 1: IP address for ASAv HA vm-B.<br>
e.g. 10.8.1.11

15. **data2SubnetName**: The data interface 2 will attach to this subnet. This maps to Nic2, the third subnet. Note, this must match an existing subnet name.<br>
e.g. data-subnet2

16. **data2SubnetIP-A**: The data interface 2: IP address for ASAv HA vm-A.<br>
e.g. 10.8.2.10

17. **data2SubnetIP-B**: The data interface 2: IP address for ASAv HA vm-B.<br>
e.g. 10.8.2.11

18. **data3SubnetName**: The data interface 3 will attach to this subnet. This maps to Nic3, the fourth subnet. Note, this must match an existing subnet name.<br>
e.g. data-subnet3

19. **data3SubnetIP-A**: The data interface 3: IP address for ASAv HA vm-A.<br>
e.g. 10.8.3.10

20. **data3SubnetIP-B**: The data interface 3: IP address for ASAv HA vm-B.<br>
e.g. 10.8.3.11

21. **vmSize**: The VM size to use for the ASAv. Standard_D3_v2 is the default.<br>
Supported sizes:<br>
  * Standard_D3
  * Standard_D4*
  * Standard_D3_v2
  * Standard_D4_v2*
  * Standard_D8_v3*
  * Standard_DS3*
  * Standard_DS4*
  * Standard_DS3_v2*
  * Standard_DS4_v2*
  * Standard_F4*
  * Standard_F8*
  * Standard_F4*
  * Standard_F8*
  * Standard_D5**
  * Standard_DS5**
  * Standard_D5_v2**
  * Standard_DS5_v2**
  * Standard_D16_v3**
  * Standard_F16**
  * Standard_F16s**
  * Standard_D8s_v3#
  * Standard_D16s_v3#
  * Standard_F8s_v2#
  * Standard_F16s_v2#

    '*' : requires ASAv version 9.13 or above.
    '**': requires ASAv version 9.15 or above.
    '#' : requires ASAv version 9.17 or above.

## References
* [Software Downloads Home](https://software.cisco.com/download/home/286119613/type/280775065/release/9.17.1)
* [ASAv deployment using VHD and ARM](https://www.cisco.com/c/en/us/td/docs/security/asa/asa917/asav/getting-started/asav-917-gsg/asav_azure.html#id_87923)
* [Azure ASAv quick start guide](https://www.cisco.com/c/en/us/td/docs/security/asa/asa917/asav/getting-started/asav-917-gsg/asav_azure.html)
* [Azure ASAv HA configuration](https://www.cisco.com/c/en/us/td/docs/security/asa/asa917/configuration/general/asa-917-general-config/ha-failover-cloud.html)

## Licensing Info
This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](../../../../LICENSE) file for details.

## Copyright
Copyright (c) 2022 Cisco Systems Inc and/or its affiliates.

## Changelog
### 9.17
- Changes to support new VM sizes:  Standard_D8s_v3, Standard_D16s_v3, Standard_F8s_v2, Standard_F16s_v2
- API version updates for Azure resources

### 9.15
- Support for Accelerated networking on the network interfaces
(now AN is enabled on the data interfaces)
- New 16 core VM sizes support
- API versions updated for Azure resources
