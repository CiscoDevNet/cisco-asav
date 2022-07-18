# Adaptive Security Appliance Virtual

## ASAv Autoscaling

This Repository provides resources to bring up ASAv Auto Scale solution.

Some of the key features of the ASAv Auto Scale include:

* Complete serverless implementation!
* Completely automated ASAv instance configuration.
* Support for Enabling / Disabling Auto Scaling feature.

## AWS GuardDuty Integration with Cisco ASAv

This solution make use of the threat analysis data/results from Amazon GuardDuty (malicious IPs generating threats, attacks etc.) and feeds the information(malicious IP) to the Cisco Adaptive Security Appliance (ASAv) to protect the underlying network and applications against future threats originating from these sources(IP).

## Cloud Deployment Templates for Cisco ASAv

This provides set of templates for deployment of ASAv in public clouds.

### Azure Templates

Azure Resource Manager(ARM) templates to deploy Cisco's ASAv and ASAv HA in Azure public cloud using custom image.

**Azure Resource Manager Templates**<br>
Azure Resource Manager templates are JSON files that contain resource descriptions and parameter definitions.
* Template file: This is the main resources file that deploys all the components within the resource group.
* Parameter file: This file includes the parameters required to successfully deploy the ASAv.

### Openstack Templates

This repository conatains heat template files to deploy the Cisco Adaptive Security Virtual Appliance (ASAv)on OpenStack environment.

## Resources

### ASAv Autoscale
* For Azure on ASAv 9.15 and above: [Code](autoscale/azure/)     |     [README](autoscale/azure/README.md)     |     [Deployment/Configuration Guide](autoscale/azure/asav_azure_autoscale_v915.pdf)

* For AWS on ASAv 9.15 and above: [Code](autoscale/aws/)     |     [README](autoscale/aws/README.md)     |     [Deployment/Configuration Guide](autoscale/aws/asav_aws_autoscale.pdf)

* For GCP on ASAv 9.17 and above: [Code](autoscale/gcp/)     |     [README](autoscale/gcp/README.md)     |     [Deployment/Configuration Guide](autoscale/gcp/asav_gcp_autoscale.pdf)

* For OCI on ASAv 9.17 and above: [Code](autoscale/oci/)     |     [README](autoscale/oci/README.md)     |     [Deployment/Configuration Guide](autoscale/oci/ASAv_Auto_Scale_Solution_on_OCI.pdf)

### Cloud Service Integration    

* AWS Guardduty: [Code](cloud-service-integration/aws/guardduty/)     |     [README](cloud-service-integration/aws/guardduty/README.md)     |     [Deployment/Configuration Guide](cloud-service-integration/aws/guardduty/Cisco_ASAv_AWS_GuardDuty_Integration_User_Configuration_Guide.pdf)


### Deployment Template
* Azure ASAv Deployment Template:
    * For ASAv 9.18: [README](deployment-templates/azure/README.md) | [ASAv](deployment-templates/azure/ASAv9.18/asav/README.md)  |   [ASAV HA](deployment-templates/azure/ASAv9.18/asav-ha/README.md)
    * For ASAv 9.17: [README](deployment-templates/azure/README.md) | [ASAv](deployment-templates/azure/ASAv9.17/asav/README.md)  |   [ASAV HA](deployment-templates/azure/ASAv9.17/asav-ha/README.md)
    * For ASAv 9.16: [README](deployment-templates/azure/README.md) | [ASAv](deployment-templates/azure/ASAv9.16/asav/README.md)  |   [ASAV HA](deployment-templates/azure/ASAv9.16/asav-ha/README.md)
    * For ASAv 9.15: [README](deployment-templates/azure/README.md) | [ASAv](deployment-templates/azure/ASAv9.15/asav/README.md)  |   [ASAV HA](deployment-templates/azure/ASAv9.15/asav-ha/README.md)
    * For ASAv 9.14: [README](deployment-templates/azure/README.md) | [ASAv](deployment-templates/azure/ASAv9.14/asav/README.md)  |   [ASAV HA](deployment-templates/azure/ASAv9.14/asav-ha/README.md)


* Openstack ASAv Heat Deployment Template: [README](deployment-templates/openstack/README.md) | [ASAv](deployment-templates/openstack/ASAv/README.md)

