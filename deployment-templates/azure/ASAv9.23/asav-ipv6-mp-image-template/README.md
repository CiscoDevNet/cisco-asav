# Azure ASAv deployment using VHD and ARM template

In addition to the Marketplace-based deployment, Cisco provides ARM templates to deploy ASAv & ASAv HA for software version listed in Azure marketplace.<br>
Using a Image and two JSON files (a Template file and a Parameter File), you can deploy and provision all the resources for the ASAv and ASAv HA in a single, coordinated operation.<br>

To deploy marketplace offer using ARM template, Update the value for softwareVersion in json file with the offer version you wish to deploy.<br>
Azure templates are JSON files that contain resource descriptions and parameter definitions.<br>

Use the instructions in the quick start guide for ASAv deployment.<br>

[ASAv deployment using VHD and ARM](https://www.cisco.com/c/en/us/td/docs/security/asa/asa923/asav/getting-started/asa-virtual-923-gsg/asav_azure.html#id_87923)<br>


## Deployment overview

1. Software Version to deploy.<br>

2. Use the ARM template to deploy a Cisco Adaptive Security Virtual Appliance(ASAv).<br>

3. Update the parameters in the parameters template file(json) and use it to provide the parameters to the ARM template.<br>

4. Review and purchase the template to deploy Cisco Adaptive Security Virtual Appliance(ASAv).<br>

5. Configure the Cisco Adaptive Security Virtual Appliance (ASAv).<br>
Refer the ASAv documentation for this.<br>

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FCiscoDevNet%2Fcisco-asav%2Fmaster%2Fdeployment-templates%2Fazure%2FASAv9.23%2Fasav-ipv6-mp-image-template%2Fasav-ipv6-mp-image-template.json)

## Parameters for the Azure ARM template:

### Pre-requisites:
1. Software version to deploy.
2. Virtual network with 4 subnets corresponding to management and 3 data subnets.

### Parameters:
1. **vmName**: The name the Cisco Adaptive Security Virtual Appliance(ASAv) will have in Azure.<br>
e.g. cisco-asav

2. **softwareVersion**: The software version text, this is the image version from the VM offer.<br>
e.g. 92311.0.0

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

7. **userData**: User Data passed down to the Virtual Machine.<br>
e.g. <br>!<br>username admin password Password@2021 privilege 15<br>!<br>

8. **virtualNetworkNewOrExisting**: This parameter determines whether a new Virtual Network should be created or an existing Virtual Network is to be used.<br>
e.g. new

9. **virtualNetworkResourceGroup**: The name of the virtual network's Resource Group.<br>
e.g. asav-vnet-rg

10. **virtualNetworkName**: The name of the virtual network.<br>
e.g. asav-vnet

11. **virtualNetworkAddressPrefixes**: IPv4 address prefix for the virtual network, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. 10.151.0.0/16

12. **virtualNetworkv6AddressPrefixes**: IPv6 address prefix for the virtual network, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. ace:cab:deca::/48

13. **Subnet1Name**:  Management subnet name.<br>
e.g. mgmt

14. **Subnet1Prefix**: Management subnet IPv4 Prefix, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. 10.151.1.0/24

15. **Subnet1IPv6Prefix**: Management subnet IPv6 Prefix, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. ace:cab:deca:1111::/64

16. **subnet1StartAddress**: IPv4 address on the mgmt interface.<br>
e.g. 10.151.1.4

17. **subnet1v6StartAddress**: IPv6 address on the mgmt interface.<br>
e.g. ace:cab:deca:1111::6

18. **Subnet2Name**: diagnostic0/0 interface will attach to this subnet.<br>
e.g. diag

19. **Subnet2Prefix**: Diag Subnet IPv4 Prefix, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. 10.151.2.0/24

20. **Subnet2IPv6Prefix**: Diag Subnet IPv6 Prefix, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. ace:cab:deca:2222::/64

21. **subnet2StartAddress**: IPv4 address on the diag interface.<br>
e.g. 10.151.2.4

22. **subnet2v6StartAddress**: IPv6 address on the diag interface.<br>
e.g. ace:cab:deca:2222::6

23. **Subnet3Name**: data1 interface will attach to this subnet.<br>
e.g. inside

24. **Subnet3Prefix**: data1 Subnet IPv4 Prefix, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. 10.151.3.0/24

25. **Subnet3IPv6Prefix**: data1 Subnet IPv6 Prefix, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. ace:cab:deca:3333::/64

26. **subnet3StartAddress**: The IPv4 address on the data1 interface.<br>
e.g. 10.151.3.4

27. **subnet3v6StartAddress**: The IPv6 address on the data1 interface.<br>
e.g. ace:cab:deca:3333::6

28. **Subnet4Name**: data2 interface will attach to this subnet.<br>
e.g. outside

29. **Subnet4Prefix**: data2 Subnet IPv4 Prefix, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. 10.151.4.0/24

30. **Subnet4IPv6Prefix**: data2 Subnet IPv6 Prefix, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. ace:cab:deca:4444::/64

31. **subnet4StartAddress**: The IPv4 address on the data2 interface.<br>
e.g. 10.151.4.4

32. **subnet4v6StartAddress**: The IPv6 address on the data2 interface.<br>
e.g. ace:cab:deca:4444::6

33. **vmSize**: The VM size to use for the ASAv. Standard_D3_v2 is the default.<br>
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

    '*' : requires ASAv version 9.13 or above.<br>
    '**': requires ASAv version 9.15 or above.<br>
    '#' : requires ASAv version 9.17 or above.<br>

18. **location**: This shouldn't be changed and should always be set to the below value.<br>
resourceGroup().location

19. **baseStorageURI**: This is used to fetch the storage account and should always be set to the below value.<br>
.blob.core.windows.net

## References
* [Software Downloads Home](https://software.cisco.com/download/home/286119613/type/280775065/release/9.23.1)
* [ASAv deployment using VHD and ARM](https://www.cisco.com/c/en/us/td/docs/security/asa/asa923/asav/getting-started/asa-virtual-923-gsg/asav_azure.html#id_87923)
* [Azure ASAv quick start guide](https://www.cisco.com/c/en/us/td/docs/security/asa/asa923/asav/getting-started/asa-virtual-923-gsg/asav_azure.html)

## Licensing Info
This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](../../../../LICENSE) file for details.

## Copyright
Copyright (c) 2022 Cisco Systems Inc and/or its affiliates.

## Changelog
### 9.22
- Template updates for Azure resources

### 9.20
- API version updates for Azure resources

### 9.19
- API version updates for Azure resources

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
