"""
Copyright (c) 2025 Cisco Systems Inc or its affiliates.

All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
--------------------------------------------------------------------------------

ASAv Cluster Deployment Tool

This script automates the deployment and deletion of ASAv clusters using AWS CloudFormation.
MAKE SURE TO COPY 'cluster_layer.zip' TO 'lambda-python-files' DIRECTORY BEFORE DEPLOYMENT!

Usage:
    Create a new cluster:
        python oneclink_cluster_deploy.py --mode create

    Delete an existing cluster:
        python oneclink_cluster_deploy.py --mode delete

    Show help:
        python oneclink_cluster_deploy.py --help

Prerequisites:
    - Python 3.x
    - AWS credentials with appropriate permissions
    - ASAv CloudFormation template
    - VPC and subnet configurations
    - Required security groups
    - S3 bucket for configurations

Configuration:
    Update the config dictionary with your values:
    1. AWS Configuration:
        - region
        - aws_access_key_id
        - aws_secret_access_key

    2. Required Parameters:
        - VpcId: Your VPC ID
        - S3BktName: S3 bucket for configurations
        - NotifyEmailID: Email for notifications
        - AmiID: ASAv AMI ID

    3. Network Configuration:
        - MgmtSubnetIds: Management subnet IDs
        - InsideSubnetIds: Inside subnet IDs
        - OutsideSubnetIds: Outside subnet IDs (dual-arm)
        - CCLSubnetIds: CCL subnet IDs
        - Security group IDs for each interface

    4. Cluster Configuration:
        - ClusterSize: Number of ASAv instances
        - NoOfAZs: Number of Availability Zones
        - DeploymentType: single-arm or dual-arm

Examples:
    1. Deploy a new cluster:
        python oneclink_cluster_deploy.py --mode create

    2. Delete an existing cluster:
        python oneclink_cluster_deploy.py --mode delete
"""

import os
import sys
import subprocess
import argparse

# Configuration Dictionary
config = {
    # AWS Configuration
    "aws_config": {
        "region": "us-east-1",
        "credentials": {"aws_access_key_id": "YOUR_ACCESS_KEY", "aws_secret_access_key": "YOUR_SECRET_KEY"}
    },
    
    # Stack Configuration
    "stack_name": "asav-cluster",
    "template_path": "../templates/deploy_asav_clustering.yaml",
    
    # Cluster Parameters
    "cluster_params": {
        # Basic Configuration
        "ClusterGrpNamePrefix": "ASAv-Cluster",  # Max length: 18 chars
        "ClusterNumber": "1",                    # Range: 1-999
        "ClusterSize": "3",                      # Number of ASAv instances
        "DeploymentType": "single-arm",          # Options: single-arm/dual-arm
        "NoOfAZs": "3",                         # Number of AZs (1-3)
        "AZ": "us-east-1a, us-east-1b, us-east-1c",  # List of AZs
        
        # Required Parameters
        "NotifyEmailID": "",                    # Email for notifications
        "S3BktName": "asav-cluster-infra-s3bucketcluster-xxxxx",    # S3 bucket for configurations
        "VpcId": "vpc-xxxxx",                            # VPC ID for deployment
        
        # Subnet Configuration
        "MgmtSubnetIds": "subnet-mgmt-1, subnet-mgmt-2, subnet-mgmt-3",     # Management subnets
        "InsideSubnetIds": "subnet-inside-1, subnet-inside-2, subnet-inside-3", # Inside subnets
        "OutsideSubnetIds": "subnet-outside-1, subnet-outside-2, subnet-outside-3",   # Outside subnets
        "CCLSubnetIds": "subnet-ccl-1, subnet-ccl-2, subnet-ccl-3",         # CCL subnets
        "LambdaSubnets": "subnet-lambda-1, subnet-lambda-2", # Lambda subnets
        
        # Network Configuration
        "CCLSubnetRanges": "10.3.90.4 10.3.90.30,10.3.91.4 10.3.91.30,10.3.92.4 10.3.92.30",  # CCL IP ranges
        
        # Security Groups
        "MgmtInterfaceSG": "sg-mgmt",        # Management security group
        "InsideInterfaceSG": "sg-inside",     # Inside security group
        "OutsideInterfaceSG": "sg-outside",     # Outside security group
        "CCLInterfaceSG": "sg-ccl",            # CCL security group
        "LambdaSG": "sg-lambda",             # Lambda security group
        
        # GWLB Configuration
        "DeployGWLBE": "No",                   # Enable GWLB endpoints
        "VpcIdLBE": "SKIP",                    # GWLB VPC ID
        "GWLBESubnetId": "SKIP",               # GWLB subnet ID
        "TargetFailover": "rebalance",         # Failover behavior
        "TgHealthPort": "7070",                # Health check port
        
        # Instance Configuration
        "InstanceType": "c5.xlarge",           # Instance type
        "LicenseType": "BYOL",                 # License type: BYOL/PAYG
        "SmartLicToken": "",                   # Smart License token
        "AssignPublicIP": "true",              # Assign public IP
        "AmiID": "ami-024f546cb9cbae1bb",      # ASAv AMI ID
        "ConfigFileURL": "",                   # Custom config URL
        "KmsArn": "",                         # KMS key ARN
        "asavPassword": "YoUrPaSsWoRd@123", # Admin password
        
        # Advanced Settings
        "InstanceMetadataServiceVersion": "V1 and V2 (token optional)",  # IMDS version
        "CpuThresholds": "10,70"              # CPU thresholds for scaling
    }
}

def build_lambda_zips():
    """Build Lambda function zip files using make.py"""
    print("\nBuilding Lambda function zip files...")
    try:
        make_script = os.path.join('..', 'make.py')
        subprocess.check_call([sys.executable, make_script, 'build'])
        print("Successfully built Lambda function zip files")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error building Lambda functions: {str(e)}")
        return False
    
def upload_lambda_zips_to_s3(session):
    """Upload Lambda zip files from target directory to S3"""
    print("\nUploading Lambda zip files to S3...")
    try:
        s3_client = session.client('s3')
        bucket_name = config['cluster_params']['S3BktName']
        target_dir = os.path.join('..', 'target')
        # Check if target directory exists
        if not os.path.exists(target_dir):
            print(f"Error: Target directory not found at {target_dir}")
            return False
        # Upload each zip file from target directory
        for filename in os.listdir(target_dir):
            if filename.endswith('.zip'):
                file_path = os.path.join(target_dir, filename)
                s3_key = f'{filename}'
                print(f"Uploading {filename} to s3://{bucket_name}/{s3_key}")
                with open(file_path, 'rb') as f:
                    s3_client.upload_fileobj(f, bucket_name, s3_key)
        print("Successfully uploaded all Lambda zip files to S3")
        return True
    except Exception as e:
        print(f"Error uploading Lambda zip files to S3: {str(e)}")
        return False
    
def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Deploy or delete ASAv cluster using CloudFormation'
    )
    parser.add_argument(
        '--mode',
        choices=['create', 'delete'],
        required=True,
        help='Specify mode: create or delete stack'
    )
    return parser.parse_args()

def create_virtual_env():
    """Create and activate virtual environment"""
    try:
        print("Creating virtual environment...")
        subprocess.check_call([sys.executable, "-m", "venv", "venv"])
        
        # Install requirements
        pip_path = "venv/bin/pip" if sys.platform != "win32" else "venv\\Scripts\\pip"
        print("Installing required packages...")
        subprocess.check_call([
            pip_path,
            "install",
            "boto3"
        ])
        print("Virtual environment setup completed successfully")
        
    except subprocess.CalledProcessError as e:
        print(f"Error creating virtual environment: {e}")
        sys.exit(1)

def get_boto3_client():
    """Create boto3 client with configured credentials"""
    import boto3
    try:
        session = boto3.Session(
            aws_access_key_id=config["aws_config"]["credentials"]["aws_access_key_id"],
            aws_secret_access_key=config["aws_config"]["credentials"]["aws_secret_access_key"],
            region_name=config["aws_config"]["region"]
        )
        return session, session.client('cloudformation')
    except Exception as e:
        print(f"Error creating AWS client: {e}")
        sys.exit(1)

def deploy_template():
    """Deploy CloudFormation template to AWS"""
    try:
        session, cfn_client = get_boto3_client()
        # Build Lambda zips
        if not build_lambda_zips():
            print("Failed to build Lambda functions. Aborting deployment.")
            sys.exit(1)
        # Upload Lambda zips to S3
        if not upload_lambda_zips_to_s3(session):
            print("Failed to upload Lambda functions to S3. Aborting deployment.")
            sys.exit(1)
        # Read template file
        with open(config["template_path"], 'r') as file:
            template_body = file.read()
        
        # Convert parameters for CloudFormation
        cfn_parameters = [
            {
                'ParameterKey': key,
                'ParameterValue': str(value)
            }
            for key, value in config["cluster_params"].items()
        ]
        
        print(f"Creating stack: {config['stack_name']}...")
        response = cfn_client.create_stack(
            StackName=config['stack_name'],
            TemplateBody=template_body,
            Parameters=cfn_parameters,
            Capabilities=[
                'CAPABILITY_IAM',
                'CAPABILITY_NAMED_IAM',
                'CAPABILITY_AUTO_EXPAND'  # Added for nested stacks and macros
            ]
        )
        
        print("Waiting for stack creation to complete (this may take 15-20 minutes)...")
        waiter = cfn_client.get_waiter('stack_create_complete')
        waiter.wait(
            StackName=config['stack_name'],
            WaiterConfig={'Delay': 30, 'MaxAttempts': 60}
        )
        
        print(f"Stack {config['stack_name']} created successfully!")
    except Exception as e:
        print(f"Error deploying template: {e}")
        sys.exit(1)

def validate_config():
    """Validate configuration parameters"""
    required_params = [
        "VpcId",
        "S3BktName",
        "NotifyEmailID",
        "AmiID"
    ]
    
    for param in required_params:
        if not config["cluster_params"].get(param):
            print(f"Error: {param} is required in configuration!")
            sys.exit(1)
    
    if not all(config["aws_config"]["credentials"].values()):
        print("Error: AWS credentials are required!")
        sys.exit(1)

def delete_stack():
    """Delete CloudFormation stack"""
    try:
        session, cfn_client = get_boto3_client()
        stack_name = config['stack_name']
        
        # Check if stack exists
        try:
            cfn_client.describe_stacks(StackName=stack_name)
        except Exception:
            print(f"Stack {stack_name} does not exist")
            return
        
        print(f"Deleting stack: {stack_name}...")
        cfn_client.delete_stack(StackName=stack_name)
        
        print("Waiting for stack deletion to complete...")
        waiter = cfn_client.get_waiter('stack_delete_complete')
        waiter.wait(
            StackName=stack_name,
            WaiterConfig={'Delay': 30, 'MaxAttempts': 60}
        )
        
        print(f"Stack {stack_name} deleted successfully!")
        
    except Exception as e:
        print(f"Error deleting stack: {e}")
        sys.exit(1)

def main():
    """Main function"""
    args = parse_args()
    
    if args.mode == 'create':
        print("Starting ASAv cluster deployment process...")
        
        # Validate configuration
        validate_config()
        
        # Create virtual environment and install packages
        create_virtual_env()
        
        # Validate template file exists
        if not os.path.exists(config["template_path"]):
            print(f"Error: Template file not found at {config['template_path']}")
            sys.exit(1)
        
        # Deploy template
        deploy_template()
    
    elif args.mode == 'delete':
        print("Starting ASAv cluster deletion process...")
        delete_stack()

if __name__ == "__main__":
    main()
