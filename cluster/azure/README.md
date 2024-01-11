# Clustering for the ASAv in  Public Cloud
Clustering lets you group ASAvs together as a single logical device. A cluster provides
all the convenience of a single device (management, integration into a network) while achieving the increased
throughput and redundancy of multiple devices. You can deploy ASAv clusters in a public
cloud using Azure, Amazon Web Services (AWS), Google Cloud Platform (GCP). Only routed firewall mode is
supported. <br>

## Deploy the Cluster in Azure
You can use the cluster with the Azure Gateway Load Balancer. To deploy a cluster in Azure, use the customized Azure Resource Manager (ARM) templates to deploy a Virtual Machine Scale Set.

## Deployment Steps

Step 1: Prepare the template.

Clone the github repository to your local folder. See https://github.com/CiscoDevNet/cisco-asav/tree/master/cluster/azure.

For GWLB-based cluster deployment, modify azure_asav_gwlb_cluster.json and azure_asav_gwlb_cluster_parameters.json with the required parameters. 

Step 2 : Log into the Azure Portal: https://portal.azure.com.

Step 3 : Create a Resource Group.

Step 4 : Create a Virtual Network with 3 subnets: Management, Data and CCL.

Step 5 : Deploy the Custom Template.

