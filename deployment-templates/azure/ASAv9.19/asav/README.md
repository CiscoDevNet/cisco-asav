# Azure ASAv deployment using VHD and ARM template

In addition to the Marketplace-based deployment, Cisco provides a compressed virtual hard disk (VHD) that you can upload to Azure and then use these ARM templates to deploy ASAv & ASAv HA in Azure.<br>
Using a Image and two JSON files (a Template file and a Parameter File), you can deploy and provision all the resources for the ASAv and ASAv HA in a single, coordinated operation.<br>

To deploy using a VHD image, you must upload the VHD image to your Azure storage account. Then, you can create an image using the uploaded disk image and use Azure Resource Manager template for deployment.<br>
Azure templates are JSON files that contain resource descriptions and parameter definitions.<br>

Use the instructions in the quick start guide for ASAv deployment.<br>

[ASAv deployment using VHD and ARM](https://www.cisco.com/c/en/us/td/docs/security/asa/asa919/asav/getting-started/asa-virtual-919-gsg/asav_azure.html#id_87923)<br>


## Deployment overview

1. Download the ASAv vhd image from Cisco Download Software download page.<br>
e.g. asav9-19-1.vhd.bz2<br>

2. Un-compress the *.bz2 & upload the VHD image to container in Azure storage account.<br>

3. Create a Image from the VHD and acquire the Resource ID of the newly created Image.<br>

4. Use the ARM template to deploy a Cisco Adaptive Security Virtual Appliance(ASAv) using the image.<br>

5. Update the parameters in the parameters template file(json) and use it to provide the parameters to the ARM template.<br>

6. Review and purchase the template to deploy Cisco Adaptive Security Virtual Appliance(ASAv).<br>

7. Configure the Cisco Adaptive Security Virtual Appliance (ASAv).<br>
Refer the ASAv documentation for this.<br>

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FCiscoDevNet%2Fcisco-asav%2Fmaster%2Fdeployment-templates%2Fazure%2FASAv9.19%2Fasav%2Fazure-asav-custom-template.json)

## Parameters for the Azure ARM template:

### Pre-requisites:
1. Image ID (created using the downloaded vhd)
2. Virtual network with 4 subnets corresponding to management and 3 data subnets.

### Parameters:
1. **vmName**: The name the Cisco Adaptive Security Virtual Appliance(ASAv) will have in Azure.<br>
e.g. cisco-asav

2. **vmImageId**: The ID of the image used for deployment. Internally, Azure associates every resource with a Resource ID.<br>
e.g. /subscriptions/<subscription-id>/resourceGroups/images-rg/providers/Microsoft.Compute/images/asav-9-19-1

3. **adminUsername**: The username for logging into ASAv. This cannot be the reserved name ‘admin’.<br>
e.g. cisco

4. **adminPassword**: The admin password for ASAv VM.<br>
e.g. Password@2021<br>
ASAv Password constraints: <br>
  * Password must be 12 to 72 characters long (Azure Password constraint)
  * must have : 1 lowercase, 1 uppercase, 1 number & 1 special characters
  * must have no more than 2 repeating or sequential(ASCII) characters<br>

5. **availabilityZone**: Specify the availability zone for deployment, Public IP and the virtual machine will be created in the specified availability zone.<br>
Set it to '0' if you do not need availability zone configuration. Ensure that selected region supports availability zones and value provided is correct.
(This must be an integer between 0-3).<br>
e.g. 0

6. **vmStorageAccount**: Your Azure storage account. You can use an existing storage account or create a new one. The storage account name must be between 3 and 24 characters, and can only contain lowercase letters and numbers.<br>
e.g. ciscoasavstorage

7. **virtualNetworkResourceGroup**: The name of the virtual network's Resource Group.<br>
e.g. asav-vnet-rg

8. **virtualNetworkName**: The name of the virtual network.<br>
e.g. asav-vnet

9. **mgmtSubnetName**: The management interface will attach to this subnet. This maps to Nic0, the first subnet. Note, this must match an existing subnet name if joining an existing network.<br>
e.g. mgmt

10. **mgmtSubnetIP**: The Management interface IP address.<br>
e.g. 10.8.0.10

11. **data1SubnetName**: The data interface 1 will attach to this subnet. This maps to Nic1, the second subnet. Note, this must match an existing subnet name.<br>
e.g. data-subnet1

12. **data1SubnetIP**: The data interface 1: IP address.<br>
e.g. 10.8.1.10

13. **data2SubnetName**: The data interface 2 will attach to this subnet. This maps to Nic2, the third subnet. Note, this must match an existing subnet name.<br>
e.g. data-subnet2

14. **data2SubnetIP**: The data interface 2: IP address.<br>
e.g. 10.8.2.10

15. **data3SubnetName**: The data interface 3 will attach to this subnet. This maps to Nic3, the fourth subnet. Note, this must match an existing subnet name.<br>
e.g. data-subnet3

16. **data3SubnetIP**: The data interface 3: IP address.<br>
e.g. 10.8.3.10

17. **vmSize**: The VM size to use for the ASAv. Standard_D3_v2 is the default.<br>
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

18. **location**: This shouldn't be changed and should always be set to the below value.<br>
resourceGroup().location

19. **baseStorageURI**: This is used to fetch the storage account and should always be set to the below value.<br>
.blob.core.windows.net

## References
* [Software Downloads Home](https://software.cisco.com/download/home/286119613/type/280775065/release/9.19.1)
* [ASAv deployment using VHD and ARM](https://www.cisco.com/c/en/us/td/docs/security/asa/asa919/asav/getting-started/asa-virtual-919-gsg/asav_azure.html#id_87923)
* [Azure ASAv quick start guide](https://www.cisco.com/c/en/us/td/docs/security/asa/asa918/asav/getting-started/asav-918-gsg/asav_azure.html)

## Licensing Info
This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](../../../../LICENSE) file for details.

## Copyright
Copyright (c) 2022 Cisco Systems Inc and/or its affiliates.

## Changelog
### 9.17
- Changes to support new VM sizes: Standard_D8s_v3, Standard_D16s_v3, Standard_F8s_v2, Standard_F16s_v2
- API version updates for Azure resources

### 9.16
- Changes to support deployment selected in Availability Zones

### 9.15
- Support for Accelerated networking on the network interfaces
(now AN is enabled on the data interfaces)
- New 16 core VM sizes support
- API versions updated for Azure resources
