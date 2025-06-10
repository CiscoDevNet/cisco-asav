# Automated Horizontal Scaling of ASAv in Azure

## Feature Overview

ASAv Auto Scale solution is a complete serverless implementation which makes use of serverless
infrastructure provided by Azure (Logic App, Azure Functions, Load Balancers, Virtual Machine Scale Set.. etc.)

Some of the key features of the ASAv Auto Scale for Azure implementation include:
*	Completely automated ASAv instance configuration
*	Support for Standard Load Balancers
*	Supports ASAv deployment in Multi-availability zones
*	Support for Enabling / Disabling Auto Scaling feature
*	Azure Resource Manager (ARM) template based deployment 
*	Support to deploy ASAv with PAYG licensing mode 

## Deployment

ARM template is used to deploy resources required by ASAv Auto Scale feature in Azure

*  ARM template will deploy serverless components (Virtual Machine Scale Set, Load Balancers, Function App, Logic App etc)
*  Function App is responsible to trigger Scale-In / Scale-Out operations and configuration of ASAv
   (Note: User needs to build Function App from the source code using Visual Studio)
*  Logic App acts as an Orchestrator to sequence the operation

Please refer [Deployment Guide](./asav_azure_autoscale.pdf) for detailed instructions on how to Build, Deploy, Configure and Manage Auto Scale solution. 
Also please refer [Deployment Guide](./asav_azure_autoscale.pdf) to understand the known limitations of this feature.

## License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](../../../LICENSE) file for details
