# Azure ASAv deployment using VHD and ARM template

In addition to the Marketplace-based deployment, Cisco provides a compressed virtual hard disk (VHD) that you can upload to Azure and then use these ARM templates to deploy ASAv & ASAv HA in Azure.<br>
Using a Image and two JSON files (a Template file and a Parameter File), you can deploy and provision all the resources for the ASAv and ASAv HA in a single, coordinated operation.<br>

To deploy using a VHD image, you must upload the VHD image to your Azure storage account. Then, you can create an image using the uploaded disk image and use Azure Resource Manager template for deployment.<br>
Azure templates are JSON files that contain resource descriptions and parameter definitions.<br>

Use the instructions in the quick start guide for ASAv deployment.<br>

[ASAv deployment using VHD and ARM](https://www.cisco.com/c/en/us/td/docs/security/asa/asa910/asav/quick-start-book/asav-910-qsg/asav_azure.html#id_87923)<br>


## Deployment overview

1. Download the ASAv vhd image from Cisco Download Software download page.<br>
e.g. asav9-14-1.vhd.bz2<br>

2. Un-compress the *.bz2 & upload the VHD image to container in Azure storage account.<br>

3. Create a Image from the VHD and acquire the Resource ID of the newly created Image.<br>

4. Use the ARM template to deploy a Cisco Adaptive Security Virtual Appliance(ASAv) using the image.<br>

5. Update the parameters in the parameters template file(json) and use it to provide the parameters to the ARM template.<br>

6. Review and purchase the template to deploy Cisco Adaptive Security Virtual Appliance(ASAv).<br>

7. Configure the Cisco Adaptive Security Virtual Appliance (ASAv).<br>
Refer the ASAv documentation for this.<br>


## Parameters for the Azure ARM template:

### Pre-requisites:
1. Image ID (created using the downloaded vhd)
2. Virtual network with 4 subnets corresponding to management and 3 data subnets.

### Parameters:
1. **vmName**: The name the Cisco Adaptive Security Virtual Appliance(ASAv) will have in Azure.<br>
e.g. cisco-asav

2. **vmImageId**: The ID of the image used for deployment. Internally, Azure associates every resource with a Resource ID.<br>
e.g. /subscriptions/73d2537e-ca44-46aa-beb2-74ff1dd61b41/resourceGroups/images-rg/providers/Microsoft.Compute/images/asav-9-14-1

3. **adminUsername**: The username for logging into ASAv. This cannot be the reserved name ‘admin’.<br>
e.g. cisco

4. **adminPassword**: The admin password. This must be 12 to 72 characters long, and include three of the following: 1 lower case, 1 upper case, 1 number, 1 special character.<br>
e.g. Password@123123

5. **vmStorageAccount**: Your Azure storage account. You can use an existing storage account or create a new one. The storage account name must be between 3 and 24 characters, and can only contain lowercase letters and numbers.<br>
e.g. ciscoasavstorage

6. **virtualNetworkResourceGroup**: The name of the virtual network's Resource Group.<br>
e.g. asav-vnet-rg

7. **virtualNetworkName**: The name of the virtual network.<br>
e.g. asav-vnet

8. **mgmtSubnetName**: The management interface will attach to this subnet. This maps to Nic0, the first subnet. Note, this must match an existing subnet name if joining an existing network.<br>
e.g. mgmt

9. **mgmtSubnetIP**: The Management interface IP address.<br>
e.g. 10.8.0.10

10. **data1SubnetName**: The data interface 1 will attach to this subnet. This maps to Nic1, the second subnet. Note, this must match an existing subnet name.<br>
e.g. data-subnet1

11. **data1SubnetIP**: The data interface 1: IP address.<br>
e.g. 10.8.1.10

12. **data2SubnetName**: The data interface 2 will attach to this subnet. This maps to Nic2, the third subnet. Note, this must match an existing subnet name.<br>
e.g. data-subnet2

13. **data2SubnetIP**: The data interface 2: IP address.<br>
e.g. 10.8.2.10

14. **data3SubnetName**: The data interface 3 will attach to this subnet. This maps to Nic3, the fourth subnet. Note, this must match an existing subnet name.<br>
e.g. data-subnet3

15. **data3SubnetIP**: The data interface 3: IP address.<br>
e.g. 10.8.3.10

16. **vmSize**: The VM size to use for the ASAv. Standard_D3_V2 is the default.<br>
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

    '*': requires ASAv version 9.13 or above.

## References
* [Software Downloads Home](https://software.cisco.com/download/home/286119613/type/280775065/release/9.14.1)
* [ASAv deployment using VHD and ARM](https://www.cisco.com/c/en/us/td/docs/security/asa/asa910/asav/quick-start-book/asav-910-qsg/asav_azure.html#id_87923)
* [Azure ASAv quick start guide](https://www.cisco.com/c/en/us/td/docs/security/asa/asa914/asav/getting-started/asav-914-gsg/asav_azure.html)

## Licensing Info
This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](../../../../LICENSE) file for details.

## Copyright
Copyright (c) 2020 Cisco Systems Inc and/or its affiliates.