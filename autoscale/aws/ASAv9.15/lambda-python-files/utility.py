"""
Copyright (c) 2020 Cisco Systems Inc or its affiliates.

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

Name:       utility.py
Purpose:    All static methods without class are written here
            It will be called in all Lambda functions
"""

import os
import sys
import logging
import json
import re
import boto3
import constant as const
from base64 import b64decode


def get_decrypted_key(encrypted_key):
    """
    Purpose:    Decrypts encrypted data using KMS Key given to lambda function
    Parameters: Encrypted key
    Returns:    Decrypted key
    Raises:
    """
    response = boto3.client('kms').decrypt(CiphertextBlob=b64decode(encrypted_key))['Plaintext']
    decrypted_key = str(response, const.ENCODING)
    return decrypted_key


def setup_logging(debug_logs="disable"):
    """
    Purpose:    Sets up logging
    Parameters: User input to disable debug logs
    Returns:    logger object
    Raises:
    """
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.INFO)
    logger = logging.getLogger()
    for h in logger.handlers:
        logger.removeHandler(h)
    h = logging.StreamHandler(sys.stdout)
    FORMAT = '%(levelname)s [%(asctime)s] (%(funcName)s)# %(message)s'
    h.setFormatter(logging.Formatter(FORMAT))
    logger.addHandler(h)
    logger.setLevel(logging.DEBUG)
    if debug_logs == "disable":
        logging.disable(logging.DEBUG)
    return logger


def put_line_in_log(var, line_type='dot'):
    """
    Purpose:    This is to help putting lines in logs
    Parameters: Variable to print between lines
    Returns:
    Raises:
    """
    if line_type == 'thick':
        logging.info("======================================== < " + var + " > ========================================")
    if line_type == 'thin':
        logging.info("---------------------------------------- < " + var + " > ----------------------------------------")
    if line_type == 'dot':
        logging.info("........................................ < " + var + " > ........................................")
    return


def get_user_input_lifecycle_asav():
    """
    Purpose:    This is to help putting lines in logs
    Parameters:
    Returns:    a dict consisting of all os.env variable
    Raises:
    """
    user_input = {
        "AutoScaleGrpName": "",
        "max_number_of_interfaces": "2",
        "NO_OF_AZs": "",
        "SUBNET_ID_LIST_1": [],
        "SUBNET_ID_LIST_2": [],
        "LB_ARN_OUTSIDE": "",
        "LB_DEREGISTRATION_DELAY": "",
        "CONFIGURE_ASAV_TOPIC_ARN": "",
        "USER_NOTIFY_TOPIC_ARN": "",
        "ASA_LICENSE_TYPE": ""
    }

    try:
        user_input['AutoScaleGrpName'] = os.environ['ASG_NAME']
        user_input['max_number_of_interfaces'] = '2'
        user_input['NO_OF_AZs'] = os.environ['NO_OF_AZs']
        user_input['ASA_LICENSE_TYPE'] = os.environ['ASA_LICENSE_TYPE']
        user_input['SUBNET_ID_LIST_1'] = os.environ['INSIDE_SUBNET'].split('::')
        user_input['SUBNET_ID_LIST_2'] = os.environ['OUTSIDE_SUBNET'].split('::')
        user_input['LB_ARN_OUTSIDE'] = os.environ['LB_ARN_OUTSIDE']
        user_input['LB_DEREGISTRATION_DELAY'] = os.environ['LB_DEREGISTRATION_DELAY']
        user_input['CONFIGURE_ASAV_TOPIC_ARN'] = os.environ['CONFIGURE_ASAV_TOPIC_ARN']
        try:
            user_input['USER_NOTIFY_TOPIC_ARN'] = os.environ['USER_NOTIFY_TOPIC_ARN']
        except KeyError as e:
            logger.debug("Exception occurred: {}".format(repr(e)))
            user_input['USER_NOTIFY_TOPIC_ARN'] = None
    except Exception as e:
        logger.error("Unable to OS environment variables")
        logger.error("Exception: {}".format(e))

    logger.debug("Environment Variables: " + json.dumps(user_input, separators=(',', ':')))
    return user_input


def get_user_input_configure_asav():
    """
    Purpose:    To get User Inputs from OS.env for Configure ASAv Lambda function
    Parameters:
    Returns:    To get dict variable of all os.env variable
    Raises:
    """
    user_input = {
        "AutoScaleGrpName": "",
        "ConfigureASAvTopic": "",
        "kms_enc": "",
        "ConfigFileUrl": "",
        "AutoScaleUserPassword": "",
        "NO_OF_AZs": "",
        "AZ_LIST": "",
        "USER_NOTIFY_TOPIC_ARN": "",
        "ASA_LICENSE_TYPE": ""
    }

    try:
        user_input['ConfigureASAvTopic'] = os.environ['CONFIGURE_ASA_TOPIC']
        if re.match(r'^arn:aws:sns:.*:.*:.*$', user_input['ConfigureASAvTopic']) is None:
            raise ValueError("Unable to find valid Topic ARN in os.env")
        try:
            user_input['USER_NOTIFY_TOPIC_ARN'] = os.environ['USER_NOTIFY_TOPIC_ARN']
        except KeyError as e:
            logger.debug("Exception occurred: {}".format(repr(e)))
            user_input['USER_NOTIFY_TOPIC_ARN'] = None
        try:
            user_input['kms_enc'] = os.environ['KMS_ENC']
        except KeyError as e:
            logger.debug("Exception occurred: {}".format(repr(e)))
            user_input['kms_enc'] = None
        user_input['AutoScaleGrpName'] = os.environ['ASG_NAME']
        user_input['ConfigFileUrl'] = os.environ['CONFIG_FILE_URL']
        user_input['NO_OF_AZs'] = os.environ['NO_OF_AZs']
        user_input['AZ_LIST'] = os.environ['AZ_LIST'].split('::')
        user_input['ASA_LICENSE_TYPE'] = os.environ['ASA_LICENSE_TYPE']
        if user_input['kms_enc'] is None:
            user_input['AutoScaleUserPassword'] = os.environ['AUTOSCALEUSER_PASSWORD']
        else:
            user_input['AutoScaleUserPassword'] = get_decrypted_key(os.environ['AUTOSCALEUSER_PASSWORD'])
        user_input['LB_ARN_OUTSIDE'] = os.environ['LB_ARN_OUTSIDE']
    except ValueError as e:
        logger.error("Error occurred: {}".format(repr(e)))
        logger.info("Check if Lambda function variables are valid!")
    except KeyError as e:
        logger.error("Error occurred: {}".format(repr(e)))
        logger.info("Please check If all Lambda function variables exist in variable section!")
    except Exception as e:
        logger.critical("Unhandled error occurred: {}".format(repr(e)))

    return user_input


def sns_msg_body_configure_asav_topic(message, to_function, category, instance_id, counter='-1'):
    """
    Purpose:    To configure message body, for Configure ASAv topic
    Parameters: message, to_function, category, instance_id, counter
    Returns:    dict variable of input parameters, with correct counter if None given
    Raises:
    """
    if counter == '-1':
        if to_function == 'vm_configure':
            counter = 5
        elif to_function == 'vm_delete':
            counter = 5
        elif to_function == 'vm_ready':
            counter = 3
        elif to_function == 'vm_license':
            counter = 5

    # Constructing a JSON object as per AWS SNS requirement
    sns_message = {
        "Description": message,
        "to_function": to_function,
        "category": category,
        "instance_id": instance_id,
        "counter": str(counter)
    }

    logger.debug("Prepared message body: " + json.dumps(sns_message, separators=(',', ':')))

    return sns_message


def sns_msg_body_user_notify_topic(message, autoscale_group, instance_id, details=None):
    """
    Purpose:    To configure message body for User notifications
    Parameters: message, asg name, instance_id, details
    Returns:    dict variable of input parameters, with correct counter if None given
    Raises:
    """
    # Constructing a JSON object as per AWS SNS requirement
    sns_message = {
        "description": message,
        "autoscale_group": autoscale_group,
        "instance_id": instance_id,
        "details": details
    }

    logger.debug("Prepared message body: " + json.dumps(sns_message, separators=(',', ':')))

    return sns_message


def get_common_member_in_list(list1, list2):
    """
    Purpose:    To get common among among two list
    Parameters: two lists
    Returns:    if only one found then common set, or [] if more found
    Raises:
    """
    list1_set = set(list1)
    list2_set = set(list2)
    common_set = list1_set.intersection(list2_set)
    logger.info("Common subnet is: %s" % common_set)
    if len(common_set) == 1:
        return list(common_set)
    elif len(common_set) > 1:
        logger.error("More than one subnets from same Availability Zones")
        return []
    else:
        logger.error("No subnets from given Availability Zones")
        return []


def make_config_url(instance_az, az_list, url_prefix):
    """
    Purpose:    To configure URL based on URL prefix given by user, attach correct file name
    Parameters: instance az, az list input by user, url prefix
    Returns:    return full url, None
    Raises:
    """
    try:
        index = az_list.index(instance_az)
    except ValueError as e:
        logger.error("Error occurred: {}".format(repr(e)))
        logger.info("Unable to find instance az in user input az list!")
    except Exception as e:
        logger.critical("Unhandled error occurred: {}".format(repr(e)))
    else:
        if index == 0:
            return url_prefix + const.AZ1_FILE_NAME
        elif index == 1:
            return url_prefix + const.AZ2_FILE_NAME
        elif index == 2:
            return url_prefix + const.AZ3_FILE_NAME
    return None

# Not used
# def make_license_config_url(url_prefix):
#     return url_prefix + const.LICENSE_FILE_NAME

logger = setup_logging(os.environ['DEBUG_LOGS'])
