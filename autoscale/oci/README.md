# Cisco ASAv AutoScale Solution for OCI

Cisco provides Terraform Templates and Oracle Functions scripts for deploying an auto-scaling solution of ASAv firewalls
using several OCI services, including Oracle Functions, Alarms, Events, Object Storage space, Event Rules and Oracle Notification services.
ASAv Auto Scale in OCI is a complete serverless implementation (i.e. no helper VMs involved in the
automation of this feature) that adds horizontal auto scaling capability to ASAv instances in the OCI
environment.<br>

The ASAv Auto Scale solution is a Terraform template-based deployment that provides:

* Completely automated ASAv deployment and configuration.
* Configuration automatically applied to scaled-out ASAv instances from Config file in the object storage space.

*Disclaimer: It is required to have prior understanding of OCI deployments & resources*

**Note: Please refer the ASAv Autoscale configuration Guide for the detailed explanation**

## Use-case

In this use-case, ASAv three network interfaces are in use: management, inside and outside.
Inside(Gig0/0) is to be placed in trusted zone same as applications or different. This interface
doesn't require default route to internet.
Outside(Gig0/1) is to be placed in un-trusted zone, where default route is set to
internet and it should have the access to the CSSM connection which is used for licensing.
Please refer Configuration guide where use-case is briefly explained.


## Steps-to-deploy

Please refer ASAv Autoscale configuration Guide for detailed explanation

## Licensing Info

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](../../../LICENSE) file for details.
