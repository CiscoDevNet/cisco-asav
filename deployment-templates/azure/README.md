# Cisco Adaptive Security Virtual Appliance (ASAv & ASAv HA) - Azure

## Azure Deployment

In addition to the Marketplace-based deployment, Cisco provides a compressed virtual hard disk (VHD) (that you can upload to Azure) and then use these ARM templates to deploy:
* [ASAv](ASAv9.20/asav/README.md)
* [ASAv HA](ASAv9.20/asav-ha/README.md)
* [ASAv IPv6 using custom image](ASAv9.20/asav-ipv6-custom-image-template)
* [ASAv IPv6 using marketplace image](ASAv9.20/asav-ipv6-mp-image-template)
<br>
Using an Image and two JSON files (a Template file and a Parameter File), you can deploy and provision all the resources for the ASAv and ASAv HA in a single, coordinated operation.<br>

To deploy using a VHD image(custom image), you must upload the VHD image to your Azure storage account. Then, you can create a image using the uploaded disk image.<br>

## Azure Resource Manager Templates
Azure Resource Manager templates are JSON files that contain resource descriptions and parameter definitions.<br>

* **Template File**  This is the main resources file that deploys all the components within the resource group.<br>
* **Parameter File** This file includes the parameters required to successfully deploy the resource. It includes details such<br>
as the subnet information, virtual machine tier and size, username and password, the name of the storage container, etc.<br>
You can customize this file for your Azure deployment environment.

*Example: Azure Resource Manager JSON Template File*
```
{
    "$schema": "http://schema.management.azure.com/schemas/2018-01-01/deploymentTemplate.json#",
    "contentVersion": "",
    "parameters": {  },
    "variables": {  },
    "resources": [  ],
    "outputs": {  }
}
```

## Resources
* Azure ASAv Deployment Template: [ASAv](ASAv9.20/asav/README.md)  |   [ASAV HA](ASAv9.20/asav-ha/README.md) | [ASAv IPv6 using custom image](ASAv9.20/asav-ipv6-custom-image-template/README.md)   | [ASAv IPv6 using marketplace image](ASAv9.20/asav-ipv6-mp-image-template/README.md)

## References
* [Software Downloads Home](https://software.cisco.com/download/home/286119613/type/280775065/release/9.20.2)
* [ASAv deployment using VHD and ARM](https://www.cisco.com/c/en/us/td/docs/security/asa/asa919/asav/getting-started/asa-virtual-919-gsg/asav_azure.html#id_87923)
* [Azure ASAv quick start guide](https://www.cisco.com/c/en/us/td/docs/security/asa/asa918/asav/getting-started/asav-918-gsg/asav_azure.html)

## Licensing Info
This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](../../LICENSE) file for details.

## Copyright
Copyright (c) 2022 Cisco Systems Inc and/or its affiliates.
