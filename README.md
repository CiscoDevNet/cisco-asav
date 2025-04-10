# Cisco Secure Firewall ASA Virtual

## ASAv Autoscaling

This Repository provides resources to bring up ASAv Auto Scale solution.

Some of the key features of the ASAv Auto Scale include:

* Complete serverless implementation!
* Completely automated ASAv instance configuration.
* Support for Enabling / Disabling Auto Scaling feature.

### Resources

* Azure ASAv 9.15 and above: [Code](autoscale/azure/)     |     [README](autoscale/azure/README.md)     |     [Deployment/Configuration Guide](autoscale/azure/asav_azure_autoscale_v919.pdf)

* AWS ASAv 9.15 and above: [Code](autoscale/aws/)     |     [README](autoscale/aws/README.md)     |     [Deployment/Configuration Guide](autoscale/aws/asav_aws_autoscale.pdf)

* GCP ASAv 9.17 and above: [Code](autoscale/gcp/)     |     [README](autoscale/gcp/README.md)     |     [Deployment/Configuration Guide](autoscale/gcp/asav_gcp_autoscale.pdf)

* OCI ASAv 9.17 and above: [Code](autoscale/oci/)     |     [README](autoscale/oci/README.md)     |     [Deployment/Configuration Guide](autoscale/oci/ASAv_Auto_Scale_Solution_on_OCI.pdf)


## ASAv Cluster

Clustering lets you group multiple ASAv units together as a single logical device.
A cluster provides all the convenience of a single device (management, integration into a network) while achieving the increased throughput and redundancy of multiple devices.
* ASAv cluster is supported on AWS from 9.19 release.
* ASAv cluster is supported on Azure from 9.20.2 release.

### Cluster Autoscale
ASA 9.23 and later now supports clustering with dynamic scaling of nodes in the Azure region. It allows you to 
scale-in or scale-out nodes from the cluster based on the network traffic. It uses logic based on the resource 
utilization statistics from Azure VMSS CPU metrics to dynamically add or remove a node from a cluster.

### Resources

* AWS ASAv 9.19 and above: [Code](cluster/aws/)     |     [README](cluster/aws/README.md)     |     [Deployment/Configuration Guide](cluster/aws/cluster-asav-public.pdf)
* Azure ASAv 9.20.2 and above: [Code](cluster/azure)     |     [README](cluster/azure/README.md)     |     [Deployment/Configuration Guide](cluster/azure/cluster-azure-public.pdf)
* Azure ASAv 9.23 and above: [Code](cluster/azure)     |     [README](cluster/azure/README.md)     |     [Deployment/Configuration Guide](cluster/azure/cluster-azure-public.pdf)

## AWS GuardDuty Integration with Cisco ASAv

This solution make use of the threat analysis data/results from Amazon GuardDuty (malicious IPs generating threats, attacks etc.) and feeds the information(malicious IP) to the Cisco Secure Firewall ASA Virtual(ASAv) to protect the underlying network and applications against future threats originating from these sources(IP).

### Resources

* AWS Guardduty: [Code](cloud-service-integration/aws/guardduty/)     |     [README](cloud-service-integration/aws/guardduty/README.md)     |     [Deployment/Configuration Guide](cloud-service-integration/aws/guardduty/Cisco_ASAv_AWS_GuardDuty_Integration_User_Configuration_Guide.pdf)

## Cloud Deployment Templates for Cisco ASAv

This provides set of templates for deployment of ASAv in public clouds.

### Azure Templates

Azure Resource Manager(ARM) templates to deploy Cisco's ASAv and ASAv HA in Azure public cloud using custom image.

**Azure Resource Manager Templates**<br>
Azure Resource Manager templates are JSON files that contain resource descriptions and parameter definitions.
* Template file: This is the main resources file that deploys all the components within the resource group.
* Parameter file: This file includes the parameters required to successfully deploy the ASAv.

#### Resources:

* For ASAv 9.20: [README](deployment-templates/azure/README.md) | [ASAv](deployment-templates/azure/ASAv9.20/asav/README.md)  |   [ASAV HA](deployment-templates/azure/ASAv9.20/asav-ha/README.md)
* For ASAv 9.19: [README](deployment-templates/azure/README.md) | [ASAv](deployment-templates/azure/ASAv9.19/asav/README.md)  |   [ASAV HA](deployment-templates/azure/ASAv9.19/asav-ha/README.md)
* For ASAv 9.18: [README](deployment-templates/azure/README.md) | [ASAv](deployment-templates/azure/ASAv9.18/asav/README.md)  |   [ASAV HA](deployment-templates/azure/ASAv9.18/asav-ha/README.md)
* For ASAv 9.17: [README](deployment-templates/azure/README.md) | [ASAv](deployment-templates/azure/ASAv9.17/asav/README.md)  |   [ASAV HA](deployment-templates/azure/ASAv9.17/asav-ha/README.md)
* For ASAv 9.16: [README](deployment-templates/azure/README.md) | [ASAv](deployment-templates/azure/ASAv9.16/asav/README.md)  |   [ASAV HA](deployment-templates/azure/ASAv9.16/asav-ha/README.md)
* For ASAv 9.15: [README](deployment-templates/azure/README.md) | [ASAv](deployment-templates/azure/ASAv9.15/asav/README.md)  |   [ASAV HA](deployment-templates/azure/ASAv9.15/asav-ha/README.md)
* For ASAv 9.14: [README](deployment-templates/azure/README.md) | [ASAv](deployment-templates/azure/ASAv9.14/asav/README.md)  |   [ASAV HA](deployment-templates/azure/ASAv9.14/asav-ha/README.md)

### Openstack Templates

This repository conatains heat template files to deploy the Cisco Secure Firewall ASA Virtual(ASAv) on OpenStack environment.

#### Resources

* Openstack ASAv Heat Deployment Template: [README](deployment-templates/openstack/README.md) | [ASAv](deployment-templates/openstack/ASAv/README.md)

## Cisco Secure Firewall ASA Container(ASAc) - Standalone

Container workloads ensure that an application runs in any computing environment agnostic of the underlying cloud infrastructure. 

Secure Firewall ASA version 9.22 and above, now supports deployment of ASA Container(ASAc) in an open source Docker or Kubernetes environment running on any cloud platform.

### Resources:

* ASAv 9.22 and above: [Code](standalone-asac/)     |     [README](standalone-asac/README.md)     |     [Deployment/Configuration Guide](standalone-asac/asa-container.pdf)
