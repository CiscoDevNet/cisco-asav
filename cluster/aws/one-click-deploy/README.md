# ASAv Multi-AZ Clustering Deployment Tools

This repository contains scripts for automated deployment and management of ASAv clusters in AWS using CloudFormation.

## Scripts Overview

### 1. One-Click Cluster Infrastructure (`oneclick_cluster_infra.py`)
Manages the basic infrastructure setup for ASAv clustering.

### 2. One-Click Cluster Deployment (`oneclick_cluster_deploy.py`)
Handles the deployment and deletion of ASAv clusters.<br>
MAKE SURE TO COPY 'cluster_layer.zip' TO 'lambda-python-files' DIRECTORY BEFORE DEPLOYMENT!<br>

## Prerequisites

- Python 3.x
- AWS account with appropriate permissions
- AWS credentials configured
- VPC and subnet configurations
- Required security groups
- S3 bucket for configurations
- ASAv CloudFormation templates

## Configuration

### AWS Credentials
```python
"aws_config": {
    "region": "us-west-2",
    "credentials": {
        "aws_access_key_id": "YOUR_ACCESS_KEY",
        "aws_secret_access_key": "YOUR_SECRET_KEY"
    }
}
```

### Required Parameters
- **VpcId**: Your VPC ID
- **S3BktName**: S3 bucket for configurations
- **NotifyEmailID**: Email for notifications
- **AmiID**: ASAv AMI ID

### Network Configuration
- **MgmtSubnetIds**: Management subnet IDs
- **InsideSubnetIds**: Inside subnet IDs
- **OutsideSubnetIds**: Outside subnet IDs (dual-arm)
- **CCLSubnetIds**: CCL subnet IDs
- **Security Groups**: IDs for each interface

### Cluster Configuration
- **ClusterSize**: Number of ASAv instances (1-16)
- **NoOfAZs**: Number of Availability Zones (1-3)
- **DeploymentType**: single-arm or dual-arm

## Usage

### Deploy New Cluster
```bash
python oneclick_cluster_deploy.py --mode create
```

### Delete Existing Cluster
```bash
python oneclick_cluster_deploy.py --mode delete
```

### Show Help
```bash
python oneclick_cluster_deploy.py --help
```

## Deployment Types

### Single-Arm Deployment
- Management interface
- Inside interface
- CCL interface

### Dual-Arm Deployment
- Management interface
- Inside interface
- Outside interface
- CCL interface

## Configuration Examples

### Basic 2-AZ Configuration
```python
"cluster_params": {
    "ClusterGrpNamePrefix": "ASAv-Cluster",
    "ClusterNumber": "1",
    "ClusterSize": "2",
    "DeploymentType": "single-arm",
    "NoOfAZs": "2",
    "AZ": ["us-west-2a", "us-west-2b"]
}
```

### High-Availability 3-AZ Configuration
```python
"cluster_params": {
    "ClusterGrpNamePrefix": "ASAv-Cluster-HA",
    "ClusterNumber": "1",
    "ClusterSize": "3",
    "DeploymentType": "dual-arm",
    "NoOfAZs": "3",
    "AZ": ["us-west-2a", "us-west-2b", "us-west-2c"]
}
```

## Troubleshooting

1. **AWS Credentials Error**
   - Verify credentials in config
   - Check AWS permissions

2. **Template Not Found**
   - Ensure template files exist in correct location
   - Verify file paths

3. **Network Configuration**
   - Validate subnet IDs
   - Check security group configurations
   - Verify VPC settings

## Support

For additional support:
- Check AWS CloudFormation documentation
- Contact your AWS administrator
- Review ASAv documentation

## License

Copyright (c) 2025 Cisco Systems Inc or its affiliates.
Licensed under the Apache License, Version 2.0