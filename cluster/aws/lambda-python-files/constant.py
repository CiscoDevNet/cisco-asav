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

Name:       constant.py
Purpose:    This is python file for Constant variables
            It will be called in all ASAv AutoScale Lambda functions
"""

# Encoding constant for password decryption function
ENCODING = "utf-8"

# Load Balancer Health probe configuration
AWS_METADATA_SERVER = '169.254.169.254'

# Lifecycle hook constants
# ------------------------------------------------------------------------------
ENI_NAME_PREFIX = "-data-interface-"
SUBNET_ID_LIST_PREFIX = "SUBNET_ID_LIST_"
SECURITY_GROUP_PREFIX = 'SECURITY_GRP_'

ENI_NAME_OF_INTERFACE_1 = "-data-interface-1"
ENI_NAME_OF_INTERFACE_2 = "-data-interface-2"
ENI_NAME_OF_INTERFACE_3 = "-data-interface-3"
ENI_NAME_OF_INTERFACE_4 = "-data-interface-4"

ASAV_SSH_PORT = 22
ASAV_USERNAME = "asavuser"
DEFAULT_PASSWORD = "AsAv_ClU3TeR44"
USE_PUBLIC_IP_FOR_SSH = False
DISABLE_USER_NOTIFY_EMAIL = False


# LifeCycleLambda Constants
# ------------------------------------------------------------------------------
# Disables or Enables execution of  business logic in LifeCycle Lambda
DISABLE_LIFECYCLE_LAMBDA = False
DISABLE_CREATE_ATTACH_INT = False
DISABLE_REGISTER_TARGET = False

# ConfigureASAvLambda Constants
# ------------------------------------------------------------------------------
# Disables or Enables execution of  business logic in ConfigureASAv Lambda
DISABLE_CONFIGURE_ASAV_LAMBDA = False

DECREMENT_CAP_IF_CLUSTER_DELETED = False
ASAV_POLL_TIME_IN_MIN_CLUSTER_READY = 10
DISABLE_CLUSTER_READY_FUNC = False
DISABLE_CLUSTER_CONFIGURE_FUNC = False
DISABLE_CLUSTER_STATUS_FUNC = False
DISABLE_LICENSE_VERIFIER_FUNC = False
DISABLE_CLUSTER_DELETE_FUNC  = False

# Configuration File Name
AZ1_FILE_NAME = 'asav-configuration.txt'
AZ2_FILE_NAME = 'asav-configuration.txt'
AZ3_FILE_NAME = 'asav-configuration.txt'

# # License Check Configurations
# LICENSE_FILE_NAME = 'license-configuration.txt'
