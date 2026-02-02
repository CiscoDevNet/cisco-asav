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

AWS CloudFormation Deployment Script for ASAv Clustering Dual-Arm Deployment

This script automates the creation and deletion of AWS CloudFormation stacks.

Usage:
    Create stack:
        python oneclick_cluster_infra.py --mode create

    Delete stack:
        python oneclick_cluster_infra.py --mode delete

    Show help:
        python oneclick_cluster_infra.py --help

Configuration:
    1. AWS Credentials (required):
        - Update aws_config section with:
            - aws_access_key_id
            - aws_secret_access_key
            - region

    2. Cluster Parameters (customize as needed):
        - ClusterName: Name of your cluster
        - ClusterNumber: Unique identifier (1-99)
        - DeploymentType: "single-arm" or "dual-arm"
        - NoOfAZs: Number of Availability Zones (1-3)
        - VPC and Subnet configurations

Prerequisites:
    - Python 3.x
    - AWS account with appropriate permissions
    - Template file at templates/infrastructure.yaml
"""
import argparse
import os
import sys
import subprocess

# Main configuration dictionary containing all settings for the deployment
config = { 
        # AWS Configuration section - Contains AWS credentials and region settings
        "aws_config": {
        "region": "us-east-1",  # AWS region where resources will be deployed
        "credentials": {
            "aws_access_key_id": "YOUR_ACCESS_KEY",      # AWS access key for authentication
            "aws_secret_access_key": "YOUR_SECRET_KEY"   # AWS secret key for authentication
          }
        },
        # CloudFormation stack configuration
        "stack_name": "asav-cluster-infra",  # Name of the CloudFormation stack
        "template_path": "../templates/infrastructure.yaml",  # Path to CloudFormation template
    
        # Detailed cluster configuration parameters
        "cluster_params": {
        "ClusterName": "asav-cls-infra",
        "ClusterNumber": "1",
        "DeploymentType": "dual-arm",  # Options: "single-arm" or "dual-arm"
        "NoOfAZs": "3",  # Options: 1, 2, or 3
        
        # VPC Network Configuration
        "VpcCidr": "10.3.0.0/16",  # CIDR block for the VPC
        
        # List of Availability Zones for deployment
        "ListOfAZs": "us-east-1a, us-east-1b, us-east-1c",
        
        # Management subnet configuration
        "MgmtSubnetNames": "MgmtSubnet-1,MgmtSubnet-2,MgmtSubnet-3",
        "MgmtSubnetCidrs": "10.3.250.0/27,10.3.251.0/27,10.3.252.0/27",
        
        # Inside subnet configuration (internal network)
        "InsideSubnetNames": "InsideSubnet-1,InsideSubnet-2,InsideSubnet-3",
        "InsideSubnetCidrs": "10.3.100.0/27,10.3.101.0/27,10.3.102.0/27",
        
        # Outside subnet configuration (external network)
        "OutsideSubnetNames": "OutsideSubnet-1,OutsideSubnet-2,OutsideSubnet-3",
        "OutsideSubnetCidrs": "10.3.200.0/27,10.3.201.0/27,10.3.202.0/27",
        
        # CCL (Cluster Control Link) subnet configuration
        "CCLSubnetNames": "CCLSubnet-1,CCLSubnet-2,CCLSubnet-3",
        "CCLSubnetCidrs": "10.3.90.0/27,10.3.91.0/27,10.3.92.0/27",
        
        # Lambda function configuration
        "LambdaAZs": "us-east-1a , us-east-1b",  # AZs for Lambda deployment
        "LambdaSubnetNames": "LambdaSubnet-1,LambdaSubnet-2",
        "LambdaSubnetCidrs": "10.3.50.0/24,10.3.51.0/24"  # Larger subnets for Lambda
    }
}

def get_boto3_client():
    """
    Create and configure a boto3 CloudFormation client with AWS credentials
    
    Returns:
        boto3.client: Configured CloudFormation client
        
    Raises:
        SystemExit: If client creation fails
    """
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

def validate_aws_config():
    """
    Validate that all required AWS configuration parameters are present
    
    Checks:
        - AWS access key ID
        - AWS secret access key
        - AWS region
        
    Raises:
        SystemExit: If any required configuration is missing
    """
    required_keys = ["aws_access_key_id", "aws_secret_access_key"]
    
    for key in required_keys:
        if not config["aws_config"]["credentials"].get(key):
            print(f"Error: AWS {key} is required!")
            sys.exit(1)
    
    if not config["aws_config"]["region"]:
        print("Error: AWS region is required!")
        sys.exit(1)

def create_virtual_env():
    """
    Create and configure a Python virtual environment
    
    Actions:
        1. Creates a new virtual environment
        2. Determines appropriate activation script based on OS
        3. Installs required packages (boto3, awscli)
        
    Raises:
        SystemExit: If virtual environment creation fails
    """
    try:
        # Create venv
        subprocess.check_call([sys.executable, "-m", "venv", "venv"])
        
        # Determine activation script path
        if sys.platform == "win32":
            activate_script = "venv\\Scripts\\activate"
        else:
            activate_script = "source venv/bin/activate"
        
        print("Virtual environment created successfully")
        print(f"Activate it using: {activate_script}")
        
        # Install requirements
        pip_path = "venv/bin/pip" if sys.platform != "win32" else "venv\\Scripts\\pip"
        subprocess.check_call([
            pip_path,
            "install",
            "boto3"
        ])
        print("Required packages installed successfully")
        
    except subprocess.CalledProcessError as e:
        print(f"Error creating virtual environment: {e}")
        sys.exit(1)

def deploy_template():
    """
    Deploy the CloudFormation template to AWS
    
    Actions:
        1. Creates CloudFormation stack
        2. Waits for stack creation to complete
        3. Displays stack outputs
        
    Raises:
        SystemExit: If deployment fails
    """
    try:
        # Initialize boto3 client
        session, cfn_client = get_boto3_client()
        
        # Read template file
        template_path = config["template_path"]
        with open(template_path, 'r') as file:
            template_body = file.read()
        
        # Convert config parameters to CloudFormation format
        cfn_parameters = [
            {
                'ParameterKey': key,
                'ParameterValue': str(value)
            }
            for key, value in config["cluster_params"].items()
        ]
        
        # Create stack
        print(f"Creating CloudFormation stack: {config['stack_name']}...")
        response = cfn_client.create_stack(
            StackName=config['stack_name'],
            TemplateBody=template_body,
            Parameters=cfn_parameters,
            Capabilities=['CAPABILITY_IAM']
        )
        
        # Wait for stack creation to complete
        print("Waiting for stack creation to complete...")
        waiter = cfn_client.get_waiter('stack_create_complete')
        waiter.wait(
            StackName=config['stack_name'],
            WaiterConfig={'Delay': 30, 'MaxAttempts': 60}
        )
        
        print(f"Stack {config['stack_name']} created successfully!")
        
        # Get stack outputs
        stack = cfn_client.describe_stacks(StackName=config['stack_name'])['Stacks'][0]
        print("\nStack Outputs:")
        for output in stack.get('Outputs', []):
            print(f"{output['OutputKey']}: {output['OutputValue']}")
        
    except Exception as e:
        print(f"Error deploying template: {e}")
        sys.exit(1)

def parse_args():
    """
    Parse command line arguments for script operation
    
    Returns:
        argparse.Namespace: Parsed command line arguments
        
    Arguments:
        --mode: Either 'create' or 'delete' to specify operation
    """
    parser = argparse.ArgumentParser(description='Deploy or delete AWS CloudFormation stack')
    parser.add_argument('--mode', choices=['create', 'delete'], required=True,
                       help='Specify the mode: create or delete stack')
    return parser.parse_args()

def empty_s3_buckets(session, cfn_client, stack_name):
    """
    Empty all S3 buckets associated with the stack before deletion
    
    Args:
        session: boto3 Session object
        cfn_client: boto3 CloudFormation client
        stack_name: Name of the stack
        
    Returns:
        None
    """
    try:
        # Get stack resources
        paginator = cfn_client.get_paginator('list_stack_resources')
        s3_client = session.client('s3')

        for page in paginator.paginate(StackName=stack_name):
            for resource in page['StackResourceSummaries']:
                # Check if resource is an S3 bucket
                if resource['ResourceType'] == 'AWS::S3::Bucket':
                    bucket_name = resource['PhysicalResourceId']
                    print(f"Emptying S3 bucket: {bucket_name}")
                    
                    # Delete all objects including versions
                    paginator = s3_client.get_paginator('list_object_versions')
                    try:
                        for page in paginator.paginate(Bucket=bucket_name):
                            objects_to_delete = []
                            
                            # Handle versions and delete markers
                            for version_type in ('Versions', 'DeleteMarkers'):
                                if version_type in page:
                                    objects_to_delete.extend([
                                        {'Key': obj['Key'], 'VersionId': obj['VersionId']}
                                        for obj in page[version_type]
                                    ])
                            
                            if objects_to_delete:
                                s3_client.delete_objects(
                                    Bucket=bucket_name,
                                    Delete={'Objects': objects_to_delete}
                                )
                    except s3_client.exceptions.NoSuchBucket:
                        print(f"Bucket {bucket_name} does not exist")
                        continue
                    
    except Exception as e:
        print(f"Error emptying S3 buckets: {e}")
        raise

def delete_stack():
    """
    Delete the CloudFormation stack from AWS
    
    Actions:
        1. Verifies stack exists
        2. Empties associated S3 buckets
        3. Initiates stack deletion
        4. Waits for deletion to complete
        
    Raises:
        SystemExit: If deletion fails
    """
    try:
        session, cfn_client = get_boto3_client()
        stack_name = config['stack_name']
        
        # Check if stack exists
        try:
            cfn_client.describe_stacks(StackName=stack_name)
        except cfn_client.exceptions.ClientError:
            print(f"Stack {stack_name} does not exist")
            return

        # Empty S3 buckets before deletion
        print("Emptying S3 buckets...")
        empty_s3_buckets(session, cfn_client, stack_name)

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
    """
    Main execution function
    
    Flow:
        1. Parse command line arguments
        2. Validate AWS configuration
        3. Execute requested operation (create/delete)
        4. Handle any errors during execution
    """
    args = parse_args()

    # Validate AWS configuration
    validate_aws_config()
    
    if args.mode == 'create':
        print("Starting deployment process...")
        # Create virtual environment and install packages
        create_virtual_env()
        
        # Validate configuration
        required_files = [config["template_path"]]
        for file_path in required_files:
            if not os.path.exists(file_path):
                print(f"Error: Required file {file_path} not found!")
                sys.exit(1)
        
        # Deploy template
        deploy_template()
    
    elif args.mode == 'delete':
        print("Starting stack deletion process...")
        delete_stack()

if __name__ == "__main__":
    main()
