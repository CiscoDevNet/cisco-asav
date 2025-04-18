# Cisco ASAv AutoScale Solution for AWS

Cisco provides CloudFormation Templates and scripts for deploying an auto-scaling tier of ASAv firewalls
using several AWS services, including Lambda, auto scaling groups, Elastic Load Balancing (ELB), Amazon
S3 Buckets, SNS, and CloudWatch.
ASAv Auto Scale in AWS is a complete serverless implementation (i.e. no helper VMs involved in the
automation of this feature) that adds horizontal auto scaling capability to ASAv instances in the AWS
environment.<br>

The ASAv Auto Scale solution is a CloudFormation template-based deployment that provides:

* Completely automated ASAv deployment and configuration.
* Configuration automatically applied to scaled-out ASAv instances from Config files in S3 bucket.
* Support for Load Balancers and multi-availability zones.
* From 9.18 release Gateway load balancer support is added, refer configuration guide for more details
* Support for enabling and disabling the Auto Scale feature.
* From 9.22 release Dual-Arm support is added, refer configuration guide for more details
* From 9.22 release, for Single-Arm topology, inside interface is registered to GWLB instead of outside interface.
* Sample configuration files are given in the directory "sample-az-configuration-txts". <br>
For deploying GWLB single-arm topology: refer sample files with 'gwlb-single-arm' prefix<br>
For deploying GWLB dual-arm topology: refer sample files with 'gwlb-dual-arm' prefix<br>
For deploying NLB single-arm topology: refer sample files with 'nlb' prefix<br>

*Disclaimer: It is required to have prior understanding of AWS deployments & resources*

**Note: Please refer [Configuration Guide](./asav_aws_autoscale.pdf) for detailed explanation**

## Solution-design
In this solution, <br>
Resources are to be deployed using CloudFormation stack, Lambda functions are used to
handle automation of initial tasks of bringing ASAv up, registering, deploying configuration on it.

There are by default 2 Lambda functions,
1. AutoScale group/Life Cycle Lambda <br>
    This lambda is responsible for adding additional 3 interfaces, attaching/detaching Gig0/1 to/from Target Groups of specified
    CloudFormation ports opened on LB input.

2. AutoScale Manager Lambda <br>
    This lambda is responsible for below tasks:<br>
    *   When a new ASAv VMs launches & becomes reachable via SSH: Configures the ASAv instance
    *   When a existing ASAv terminates: during grace-period, it removes license on ASAv
    *   Health Doctor module,
        * If Un-healthy alarm for one of TG goes to ALARM state, then it triggers Lambda for Health Doctor module
        * Checks if there are any un-healthy IPs in Target groups. If there are any then if corresponding instance is an ASAv which is running for more than an hour
          then delete the instance & AWS will launch new instance to re-fill it.
          If instance is running for less than an hour, then ignore it.
          If IP address belongs to any other instance or not from any instance, then de-register IP address

Scaling Policies can be created based only on CPU using AWS Dynamic Scaling only.

## Steps-to-deploy

Please refer [Configuration Guide](./asav_aws_autoscale.pdf) for detailed explanation

## Licensing Info

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](../../../LICENSE) file for details.