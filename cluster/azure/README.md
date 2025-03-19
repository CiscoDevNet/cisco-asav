# Clustering for the ASAv in  Public Cloud
Clustering lets you group ASAvs together as a single logical device. A cluster provides
all the convenience of a single device (management, integration into a network) while achieving the increased
throughput and redundancy of multiple devices. You can deploy ASAv clusters in a public
cloud using Azure, Amazon Web Services (AWS), Google Cloud Platform (GCP). Only routed firewall mode is
supported. <br>

## Deploy the Cluster in Azure
You can use the cluster with the Azure Gateway Load Balancer. To enable scaling up virtual machine workloads during traffic spikes and scaling down during off-peak hours to optimize costs, cluster nodes must scale automatically alongside the applications. This capability not only ensures application security but also reduces infrastructure costs by eliminating the need for over-provisioning security to accommodate peak demands.

**Starting with release 9.23**, ASAv clustering now supports dynamic auto-scaling by default. To deploy the ASAv cluster or ASAv cluster autoscale, use the customized Azure Resource Manager (ARM) templates which deploys a Virtual Machine Scale Set along with required resources.

## Deployment Steps

Step 1: Prepare the template.

Clone the github repository to your local folder. See https://github.com/CiscoDevNet/cisco-asav/tree/master/cluster/azure.

For GWLB-based cluster deployment, use the azure_asav_gwlb_cluster.json and update the azure_asav_gwlb_cluster_parameters.json with the required parameters.

Step 2 : Log into the Azure Portal: https://portal.azure.com.

Step 3 : Create a Resource Group.

Step 4 : Create a Virtual Network with 4 subnets: Management, Data, CCL and Function Application Subnet.

Step 5 : Deploy the Template azure_asav_gwlb_cluster.json using the updated parameters. Please refer [Deployment/Configuration Guide](./cluster-azure-public.pdf) for detailed steps.

