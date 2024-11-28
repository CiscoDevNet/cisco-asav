"""
Copyright (c) 2024 Cisco Systems Inc or its affiliates.

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

## Metadata Server for health probes
AWS_METADATA_SERVER = '169.254.169.254' ## Required for NLB case only

# Lifecycle hook constants
# ------------------------------------------------------------------------------
ENI_NAME_PREFIX = "-data-interface-"
SUBNET_ID_LIST_PREFIX = "SUBNET_ID_LIST_"
SECURITY_GROUP_PREFIX = 'SECURITY_GRP_' ## Required for GWLB case only

ENI_NAME_OF_INTERFACE_1 = "-data-interface-1"
ENI_NAME_OF_INTERFACE_2 = "-data-interface-2"
ENI_NAME_OF_INTERFACE_3 = "-data-interface-3" ## Required for NLB case only
ENI_NAME_OF_INTERFACE_4 = "-data-interface-4" ## Required for NLB case only

ASAV_SSH_PORT = 22
ASAV_USERNAME = "autoscaleuser"
DEFAULT_PASSWORD = "AsAv_AuT0Scale"
USE_PUBLIC_IP_FOR_SSH = False

DISABLE_USER_NOTIFY_EMAIL = False

# LifeCycleLambda Constants
# ------------------------------------------------------------------------------
# Disables or Enables execution of business logic in LifeCycle Lambda
DISABLE_LIFECYCLE_LAMBDA = False
DISABLE_CREATE_ATTACH_INT = False
DISABLE_REGISTER_TARGET = False

# ConfigureASAvLambda Constants
# ------------------------------------------------------------------------------
# Disables or Enables execution of business logic in ConfigureASAv Lambda
DISABLE_CONFIGURE_ASAV_LAMBDA = False

DECREMENT_CAP_IF_VM_DELETED = False
ASAV_POLL_TIME_IN_MIN_VM_READY = 10

DISABLE_VM_READY_FUNC = False
DISABLE_VM_CONFIGURE_FUNC = False
DISABLE_LICENSE_VERIFIER_FUNC = False
DISABLE_VM_DELETE_FUNC = False

# Configuration File Names
# NLB_CONFIG_PREFIX = 'nlb-'
# GWLB_SINGLE_ARM_CONFIG_PREFIX = 'gwlb-single-arm-'
# GWLB_DUAL_ARM_CONFIG_PREFIX = 'gwlb-dual-arm-'
AZ1_FILE_NAME = 'az1-configuration.txt'
AZ2_FILE_NAME = 'az2-configuration.txt'
AZ3_FILE_NAME = 'az3-configuration.txt'

# Constants for Health Doctor
DISABLE_HEALTH_DOCTOR = False
UNHEALTHY_DAYS_THRESHOLD = 0
UNHEALTHY_HOURS_THRESHOLD = 1
DECREMENT_CAP_IF_VM_REMOVED_BY_DOCTOR = False