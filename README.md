
## ASAv Autoscaling

This Repository provides resources to bring up ASAv Auto Scale solution.

Some of the key features of the ASAv Auto Scale include:

* Complete serverless implementation!
* Completely automated ASAv instance configuration.
* Support for Enabling / Disabling Auto Scaling feature.

## Cloud Deployment Templates for Cisco ASAv

This provides set of templates for deployment of ASAv in public clouds.

### Azure Templates

Azure Resource Manager(ARM) templates to deploy Cisco's ASAv and ASAv HA in Azure public cloud using custom image.

**Azure Resource Manager Templates**<br>
Azure Resource Manager templates are JSON files that contain resource descriptions and parameter definitions.
* Template file: This is the main resources file that deploys all the components within the resource group.
* Parameter file: This file includes the parameters required to successfully deploy the ASAv.

## Resources

* Azure ASAv Deployment Template for ASAv 9.14: [README](deployment-templates/azure/README.md) | [ASAv](deployment-templates/azure/ASAv9.14/asav/README.md)  |   [ASAV HA](deployment-templates/azure/ASAv9.14/asav-ha/README.md)

* Azure ASAv Deployment Template for ASAv 9.15: [README](deployment-templates/azure/README.md) | [ASAv](deployment-templates/azure/ASAv9.15/asav/README.md)  |   [ASAV HA](deployment-templates/azure/ASAv9.15/asav-ha/README.md)

* ASAv Auto Scaling for Azure : [Code](autoscale/azure/ASAv9.15/)     |     [README](autoscale/azure/ASAv9.15/README.md)     |     [Deployment/Configuration Guide](autoscale/azure/ASAv9.15/asav_azure_autoscale_v915.pdf)

* ASAv Auto Scaling for AWS [Code](autoscale/aws/ASAv9.15/)     |     [README](autoscale/aws/ASAv9.15/README.md)     |     [Deployment/Configuration Guide](autoscale/aws/ASAv9.15/asav_aws_autoscale_v915.pdf)
