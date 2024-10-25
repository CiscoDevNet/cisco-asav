"""
Copyright (c) 2022 Cisco Systems Inc or its affiliates.

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

Name:       configure_asav.py
Purpose:    This python file has Lambda handler for ConfigureASAv Lambda
"""

from datetime import datetime, timezone
import json
import os
import time
import utility as utl
from asav import ASAvInstance
from aws import SimpleNotificationService, EC2Instance, CloudWatch, ElasticLoadBalancer, AutoScaleGroup
import constant as const

# Setup Logging
logger = utl.setup_logging(os.environ['DEBUG_LOGS'])
# Get User input
user_input = utl.get_user_input_configure_asav()

def lambda_handler(event, context):
    """
    Purpose:    Configure ASAv Lambda, to configure ASAv
    Parameters: AWS Events(CloudWatch), SNS events, Unhealthy threshold Alarm
    Returns:
    Raises:
    """
    utl.put_line_in_log('Configure ASAv Lambda Handler started', 'thick')
    logger.info("Received Lambda Event: " + json.dumps(event, separators=(',', ':')))

    if const.DISABLE_CONFIGURE_ASAV_LAMBDA is True:
        logger.info("ConfigureASAvLambda running is disabled! Check constant.py")
        utl.put_line_in_log('Configure ASAv Lambda Handler finished', 'thick')
        return

    # SNS Event
    try:
        if event["Records"][0]["EventSource"] == "aws:sns":
            sns_data = event["Records"][0]["Sns"]
            handle_sns_event(sns_data)
            utl.put_line_in_log('Configure ASAv Lambda Handler finished', 'thick')
            return
    except Exception as e:
        logger.info("Received an event but not a SNS notification event")
        logger.debug(str(e))
        pass

    # EC2 CloudWatch Event
    try:
        if event["detail-type"] == "EC2 Instance Launch Successful":
            try:
                instance_id = event['detail']['EC2InstanceId']
                handle_ec2_launch_event(instance_id)
                utl.put_line_in_log('Configure ASAv Lambda Handler finished', 'thick')
                return
            except Exception as e:
                logger.error("Unable to get instance ID from event!")
                logger.error("Error occurred {}".format(repr(e)))
                utl.put_line_in_log('Configure ASAv Lambda Handler finished', 'thick')
                return

        elif event["detail-type"] == "EC2 Instance Terminate Successful":
            try:
                instance_id = event['detail']['EC2InstanceId']
                handle_ec2_terminate_event(instance_id)
                utl.put_line_in_log('Configure ASAv Lambda Handler finished', 'thick')
                return
            except Exception as e:
                logger.error("Unable to get instance ID from event!")
                logger.error("Error occurred {}".format(repr(e)))
                utl.put_line_in_log('Configure ASAv Lambda Handler finished', 'thick')
                return
    except Exception as e:
        logger.info("Received an event but not an EC2 CloudWatch event")
        logger.debug(str(e))
        pass

    utl.put_line_in_log('Configure ASAv Lambda Handler finished', 'thick')
    return


def handle_sns_event(sns_data):
    """
    Purpose:    Handler for SNS event
    Parameters: SNS data from Lambda handler
    Returns:
    Raises:
    """
    utl.put_line_in_log('SNS Handler', 'thin')
    logger.debug("SNS Message: " + json.dumps(sns_data, separators=(',', ':')))

    # SNS class initialization
    sns = SimpleNotificationService()

    sns_msg_attr = json.loads(sns_data['Message'])
    logger.info("SNS Message: " + json.dumps(sns_msg_attr, separators=(',', ':')))

    if sns_msg_attr is None:
        logger.critical("Unable to get required attributes from SNS message!")
        utl.put_line_in_log('SNS Handler Finished', 'thin')
        return

    try:  # This check is to see if event is for health doctor
        logger.debug("Logging Instance ID: %s ", sns_msg_attr['instance_id'])
    except KeyError as e:
        logger.debug("Exception occurred {}".format(repr(e)))

    try:
        if sns_msg_attr['instance_id'] is None:
            logger.critical("Received instance_id None!")
            utl.put_line_in_log('SNS Handler Finished', 'thin')
            return
        if int(sns_msg_attr['counter']) <= 0 and sns_msg_attr['to_function'] != 'cluster_delete':
            logger.critical("Has ran out of retries! calling cluster_delete...")
            if user_input['USER_NOTIFY_TOPIC_ARN'] is not None:
                # Email to user
                details_of_the_device = None
                message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + \
                                  sns_msg_attr['instance_id'] + ' Unable to complete ' + sns_msg_attr['to_function']
                msg_body = utl.sns_msg_body_user_notify_topic('Unable to complete '+sns_msg_attr['to_function'],
                                                              user_input['AutoScaleGrpName'],
                                                              sns_msg_attr['instance_id'], details_of_the_device)
                sns.publish_to_topic(user_input['USER_NOTIFY_TOPIC_ARN'], message_subject, msg_body)
            utl.put_line_in_log('SNS Handler Finished', 'thin')
            return
        elif int(sns_msg_attr['counter']) <= 0 and sns_msg_attr['to_function'] == 'cluster_delete':
            logger.critical("Unable to delete device %s" % sns_msg_attr['instance_id'])
            if user_input['USER_NOTIFY_TOPIC_ARN'] is not None:
                # Email to user
                details_of_the_device = None
                message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + \
                                  sns_msg_attr['instance_id'] + ' unable to remove instance'
                msg_body = utl.sns_msg_body_user_notify_topic('Instance Not Removed', user_input['AutoScaleGrpName'],
                                                              sns_msg_attr['instance_id'], details_of_the_device)
                sns.publish_to_topic(user_input['USER_NOTIFY_TOPIC_ARN'], message_subject, msg_body)
                # -------------
            utl.put_line_in_log('SNS Handler Finished', 'thin')
            return
    except KeyError as e:
        logger.error("Unable to get one of required parameter from SNS Message body: {}".format(repr(e)))
        utl.put_line_in_log('SNS Handler Finished', 'thin')
        return


    # ASAv class initialization
    asa = ASAvInstance(sns_msg_attr['instance_id'])

    instance_state = asa.get_instance_state()
    logger.info("Instance %s " % sns_msg_attr['instance_id'] + "is in %s state" % instance_state)
    if sns_msg_attr['to_function'] == 'cluster_delete':
        pass
    elif instance_state == 'running' or instance_state == 'pending':
        pass
    else:
        logger.error("Device in %s state, can't be handled by %s function"
                     % (instance_state, sns_msg_attr['to_function']))
        utl.put_line_in_log('SNS Handler Finished', 'thin')
        return

    logger.info("Continue to execute action of " + sns_msg_attr['to_function'])

    # AutoscaleGroup initialization
    aws_grp = aws_asg_cls_init()

    if sns_msg_attr['to_function'] == 'cluster_ready':
        if const.DISABLE_CLUSTER_READY_FUNC is True:
            logger.info(sns_msg_attr['to_function'] + " function is disabled! Check constant.py")
            utl.put_line_in_log('SNS Handler Finished', 'thin')
            return
        asa.create_instance_tags('Name', asa.vm_name)  # To put Name tag on instance
        if sns_msg_attr['category'] == 'FIRST':
            logger.info("Device is booting.. Waiting...")
            time.sleep(120)

            if execute_cluster_ready_first(asa) == 'SUCCESS':
                logger.info("SSH to ASAv is successful, Next action: Configuration")
                if not const.DISABLE_CLUSTER_CONFIGURE_FUNC:
                    message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + 'instance configure' + ' ' + \
                                      sns_msg_attr['instance_id']
                    msg_body = utl.sns_msg_body_configure_asav_topic('Cluster node is ready', 'cluster_configure',  'FIRST',
                                                                     sns_msg_attr['instance_id'])
                    sns.publish_to_topic(user_input['ConfigureASAvTopic'], message_subject, msg_body)
                else:
                    logger.info(" cluster_configure function is disabled! Check constant.py")
            else:
                logger.warn("SSH to ASAv with instance_id: %s is un-successful, Retrying..." %
                            sns_msg_attr['instance_id'])
                message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + 'instance poll' + ' ' + \
                                  sns_msg_attr['instance_id']
                msg_body = utl.sns_msg_body_configure_asav_topic('Check Instance is ready', 'cluster_ready', 'FIRST',
                                                                 sns_msg_attr['instance_id'],
                                                                 str(int(sns_msg_attr['counter']) - 1))
                sns.publish_to_topic(user_input['ConfigureASAvTopic'], message_subject, msg_body)

                
    elif sns_msg_attr['to_function'] == 'cluster_configure':
        if const.DISABLE_CLUSTER_CONFIGURE_FUNC is True:
            logger.info(sns_msg_attr['to_function'] + " function is disabled! Check constant.py")
            utl.put_line_in_log('SNS Handler Finished', 'thin')
            return

        if sns_msg_attr['category'] == 'FIRST':
            if execute_cluster_configure_first(asa) == 'SUCCESS':
                time.sleep(60)
                if not const.DISABLE_CLUSTER_STATUS_FUNC:
                    logger.info("Configuration of ASAv is successful, Next action: Cluster status")
                    message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + 'cluster status' + ' ' + \
                                      sns_msg_attr['instance_id']
                    msg_body = utl.sns_msg_body_configure_asav_topic('Cluster node is configured', 'cluster_status',  'FIRST',
                                                                     sns_msg_attr['instance_id'])
                    sns.publish_to_topic(user_input['ConfigureASAvTopic'], message_subject, msg_body)
                else:
                    logger.info(" cluster_status function is disabled! Check constant.py")
                if user_input['USER_NOTIFY_TOPIC_ARN'] is not None:
                    # Email to user
                    details_of_the_device = json.dumps(asa.get_instance_tags())
                    message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + \
                                      sns_msg_attr['instance_id'] + ' ' + 'instance configured'
                    msg_body = utl.sns_msg_body_user_notify_topic('Cluster node Configured', user_input['AutoScaleGrpName'],
                                                                  sns_msg_attr['instance_id'], details_of_the_device)
                    sns.publish_to_topic(user_input['USER_NOTIFY_TOPIC_ARN'], message_subject, msg_body)
                    # -------------
            else:
                logger.warn("Configuration failed! trying again in next cycle...")
                message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + 'instance configure' + ' ' + \
                                  sns_msg_attr['instance_id']
                msg_body = utl.sns_msg_body_configure_asav_topic('Cluster node is not configured', 'cluster_configure', 'FIRST',
                                                                 sns_msg_attr['instance_id'],
                                                                 str(int(sns_msg_attr['counter']) - 1))
                sns.publish_to_topic(user_input['ConfigureASAvTopic'], message_subject, msg_body)

    elif sns_msg_attr['to_function'] == 'cluster_status':
        if const.DISABLE_CLUSTER_STATUS_FUNC is True:
            logger.info(sns_msg_attr['to_function'] + " function is disabled! Check constant.py")
            utl.put_line_in_log('SNS Handler Finished', 'thin')
            return
        
        if sns_msg_attr['category'] == 'FIRST':
            if verify_cluster_status(aws_grp, asa) == 'SUCCESS':
                if not const.DISABLE_LICENSE_VERIFIER_FUNC:
                    logger.info("Cluster is successfully formed!, Next action: Cluster license")
                    message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + 'cluster license' + ' ' + \
                                      sns_msg_attr['instance_id']
                    msg_body = utl.sns_msg_body_configure_asav_topic('Cluster node Joined', 'cluster_license',  'FIRST',
                                                                     sns_msg_attr['instance_id'])
                    sns.publish_to_topic(user_input['ConfigureASAvTopic'], message_subject, msg_body)
                else:
                    logger.info(" cluster_license function is disabled! Check constant.py")
                if user_input['USER_NOTIFY_TOPIC_ARN'] is not None:
                    # Email to user
                    details_of_the_device = json.dumps(asa.get_instance_tags())
                    message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + \
                                      sns_msg_attr['instance_id'] + ' ' + 'cluster formed'
                    msg_body = utl.sns_msg_body_user_notify_topic('Cluster node Joined', user_input['AutoScaleGrpName'],
                                                                  sns_msg_attr['instance_id'], details_of_the_device)
                    sns.publish_to_topic(user_input['USER_NOTIFY_TOPIC_ARN'], message_subject, msg_body)
                    # -------------
            else:
                logger.warn("Cluster status failed! trying again in next cycle...")
                message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + 'cluster status' + ' ' + \
                                  sns_msg_attr['instance_id']
                msg_body = utl.sns_msg_body_configure_asav_topic('Cluster not formed', 'cluster_status', 'FIRST',
                                                                 sns_msg_attr['instance_id'],
                                                                 str(int(sns_msg_attr['counter']) - 1))
                sns.publish_to_topic(user_input['ConfigureASAvTopic'], message_subject, msg_body)

    elif sns_msg_attr['to_function'] == 'cluster_license':
        if const.DISABLE_LICENSE_VERIFIER_FUNC is True:
            logger.info(sns_msg_attr['to_function'] + " function is disabled! Check constant.py")
            utl.put_line_in_log('SNS Handler Finished', 'thin')
            return
        if sns_msg_attr['category'] == 'FIRST':
            if execute_cluster_license_first(asa) == 'SUCCESS':
                logger.info("Licensing of ASAv is successful!")
                details_of_the_device = json.dumps(asa.get_instance_tags())
                logger.info(details_of_the_device)
                if user_input['USER_NOTIFY_TOPIC_ARN'] is not None:
                    # Email to user
                    message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + \
                                      sns_msg_attr['instance_id'] + ' ' + 'instance licensed'
                    msg_body = utl.sns_msg_body_user_notify_topic('Cluster node Licensed',
                                                                  user_input['AutoScaleGrpName'],
                                                                  sns_msg_attr['instance_id'], details_of_the_device)
                    sns.publish_to_topic(user_input['USER_NOTIFY_TOPIC_ARN'], message_subject, msg_body)
                    # -------------
            else:
                logger.warn("Licensing failed! trying again in next cycle...")
                message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + 'instance configure' + ' ' + \
                                  sns_msg_attr['instance_id']
                msg_body = utl.sns_msg_body_configure_asav_topic('Cluster node not configured with license', 'cluster_license',
                                                                 'FIRST',
                                                                 sns_msg_attr['instance_id'],
                                                                 str(int(sns_msg_attr['counter']) - 1))
                sns.publish_to_topic(user_input['ConfigureASAvTopic'], message_subject, msg_body)

    elif sns_msg_attr['to_function'] == 'cluster_delete':
        if sns_msg_attr['category'] == 'FIRST':
            if execute_cluster_delete_first(asa) == 'SUCCESS':
                logger.info("Instance has been deleted! ")
            else:
                logger.critical("Unable to delete instance!")
                message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + 'instance delete' + ' ' + \
                                  sns_msg_attr['instance_id']
                msg_body = utl.sns_msg_body_configure_asav_topic('Instance not deleted from ASG', 'cluster_delete', 'FIRST',
                                                                 sns_msg_attr['instance_id'],
                                                                 str(int(sns_msg_attr['counter']) - 1))
                sns.publish_to_topic(user_input['ConfigureASAvTopic'], message_subject, msg_body)

        if sns_msg_attr['category'] == 'SECOND':
            if execute_vm_delete_second(asa) == 'SUCCESS':
                logger.info("Instance license de-registration command has been run!")
            else:
                logger.critical("Unable to de-register license for the instance!")
                message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + 'instance de-register' + ' ' + \
                                  sns_msg_attr['instance_id']
                msg_body = utl.sns_msg_body_configure_asav_topic('license deregistration failed', 'cluster_delete', 'SECOND',
                                                                 sns_msg_attr['instance_id'],
                                                                 str(int(sns_msg_attr['counter']) - 1))
                sns.publish_to_topic(user_input['ConfigureASAvTopic'], message_subject, msg_body)

    utl.put_line_in_log('SNS Handler Finished', 'thin')
    return


def handle_ec2_launch_event(instance_id):
    """
    Purpose:    Handler for EC2 launch event
    Parameters: Instance Id
    Returns:
    Raises:
    """
    utl.put_line_in_log('EC2 Launch Handler', 'thin')
    # SNS class initialization
    sns = SimpleNotificationService()
    if instance_id is not None:
        logger.info("Received EC2 launch notification for instance-id: " + str(instance_id))

        # ASAv class initialization
        instance = ASAvInstance(instance_id)
        instance_state = instance.get_instance_state()
        interfaces_ip = instance.get_instance_interfaces_ip()
        if interfaces_ip is None:
            logger.warn("Unable to get IPs of the instance" + instance_id)
            message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + 'instance poll' + ' ' + instance_id
            msg_body = utl.sns_msg_body_configure_asav_topic('Check Instance is ready', 'cluster_ready', 'FIRST', instance_id)
            sns.publish_to_topic(user_input['ConfigureASAvTopic'], message_subject, msg_body)
        if instance_state == 'running' or instance_state == 'pending':
            logger.info("Instance %s is in state: %s" % (instance_id, instance_state))
            message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + 'instance poll' + ' ' + instance_id
            msg_body = utl.sns_msg_body_configure_asav_topic('Check Instance is ready', 'cluster_ready', 'FIRST', instance_id)
            sns.publish_to_topic(user_input['ConfigureASAvTopic'], message_subject, msg_body)
        else:
            logger.warn("Instance %s is in state: %s" % (instance_id, instance_state))

        if user_input['USER_NOTIFY_TOPIC_ARN'] is not None:
            # Email to user
            details_of_the_device = None
            message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + instance_id + ' ' + \
                              'instance is launched'
            msg_body = utl.sns_msg_body_user_notify_topic('Instance Launched', user_input['AutoScaleGrpName'],
                                                          instance_id, details_of_the_device)
            sns.publish_to_topic(user_input['USER_NOTIFY_TOPIC_ARN'], message_subject, msg_body)
            # -------------
    else:
        logger.critical("Received instance_id None!")

    utl.put_line_in_log('EC2 Launch Handler finished', 'thin')
    return


def handle_ec2_terminate_event(instance_id):
    """
    Purpose:    Handler for EC2 terminate event
    Parameters: Instance Id
    Returns:
    Raises:
    """
    utl.put_line_in_log('EC2 Terminate Handler', 'thin')
    logger.info("Received EC2 termination notification for instance-id: " + str(instance_id))

    # SNS class initialization
    sns = SimpleNotificationService()

    if instance_id is not None:  # Since Instance termination initiated, delete entries
        logger.info("Instance termination has been initiated: " + instance_id)
        if not const.DISABLE_CLUSTER_DELETE_FUNC:
            logger.info("Initiating cluster_delete function via SNS")
            message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + 'instance delete' + ' ' + instance_id
            msg_body = utl.sns_msg_body_configure_asav_topic('Deleting cluster node..', 'cluster_delete', 'FIRST', instance_id)
            sns.publish_to_topic(user_input['ConfigureASAvTopic'], message_subject, msg_body)

        if user_input['USER_NOTIFY_TOPIC_ARN'] is not None:
            # Email to user
            details_of_the_device = None
            message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + instance_id + ' ' + \
                              'instance is terminated'
            msg_body = utl.sns_msg_body_user_notify_topic('Instance Terminated', user_input['AutoScaleGrpName'],
                                                          instance_id, details_of_the_device)
            sns.publish_to_topic(user_input['USER_NOTIFY_TOPIC_ARN'], message_subject, msg_body)
            # -------------

    utl.put_line_in_log('EC2 Terminate Handler finished', 'thin')
    return


def execute_cluster_ready_first(asa):
    """
    Purpose:    This polls ASAv instance for it's SSH accessibility
    Parameters: Object of type ASAvInstance class
    Returns:    SUCCESS, FAIL
    Raises:
    """
    poll_asav = asa.poll_asav_ssh(const.ASAV_POLL_TIME_IN_MIN_CLUSTER_READY)
    if poll_asav == "SUCCESS":
        request_response = asa.configure_hostname()
        if request_response != 'SUCCESS':
            asa.configure_hostname()
        asa.create_instance_tags('ASAvConnectionStatus', 'AVAILABLE')
        return 'SUCCESS'
    return 'FAIL'


def execute_cluster_configure_first(asa):
    """
    Purpose:    This configures cluster
    Parameters: Object of ASAvInstance class
    Returns:    SUCCESS, FAIL
    Raises:
    """
    # Apply device configuration
    asa.create_instance_tags('ASAvConfigurationStatus', 'ONGOING')
    local_file_name = 'Configuration.txt'
    asav_local_file_path = 'disk0:' + local_file_name
    octet = asa.get_instance_interfaces_ip()['private_ip'].split('.')[3]

    if user_input['ConfigFileUrl'] and asa.get_public_ip():
        if asa.run_copy_file_running_config(user_input['ConfigFileUrl'], asav_local_file_path) == "SUCCESS":
            if asa.verify_configuration_file_copy(local_file_name) == "SUCCESS":
                logger.info("ASAv configuration written on the device..!")
            else:
                logger.error("Unable to write ASAv configuration on the device..!")
                asa.create_instance_tags('ASAvConfigurationStatus', 'FAIL')
                return 'FAIL'
                
    az = asa.get_instance_availability_zone(asa.instance_id)
    az_in_char = az[len(az)-1]
    az_in_num = str(ord(az_in_char.lower()) - ord('a') + 1)
    number_of_azs = user_input['NO_OF_AZs']
    if asa.configure_cluster(octet, az_in_char, az_in_num, number_of_azs) == "SUCCESS":
        logger.info("Cluster configuration successfully applied..!")
        asa.create_instance_tags('ASAvConfigurationStatus', 'DONE')
        return 'SUCCESS'
    asa.create_instance_tags('ASAvConfigurationStatus', 'FAIL')
    logger.info("Configuration hasn't been applied!")
    return 'FAIL'

def execute_cluster_license_first(asa):
    """
    Purpose:    This configures Licensing of ASAv instance
    Parameters: Object of ASAvInstance class
    Returns:    SUCCESS, FAIL
    Raises:
    """
    # Apply device license configuration
    if user_input['ASA_LICENSE_TYPE'] == 'PAYG':
        logger.info("Found PAYG Licensing type in User Input")
        logger.info("Verifying License status inside the device")
        if asa.verify_aws_licensing() == 'SUCCESS':
            if asa.verify_asav_payg_licensed() == 'SUCCESS':
                logger.info("ASAv is found with AWS Licensing type")
                asa.create_instance_tags('ASAvLicenseStatus', 'LICENSED')
                return 'SUCCESS'
        time.sleep(30)
    elif user_input['ASA_LICENSE_TYPE'] == 'BYOL':
        logger.info("Found BYOL Licensing type in User Input")
        logger.info("Verifying License status inside the device")
        if asa.verify_asa_smart_licensing_enabled() == 'SUCCESS':
            if asa.verify_asav_byol_licensed() == 'SUCCESS' and asa.verify_asa_license_authorized() == 'SUCCESS':
                logger.info("ASAv is found with Smart Licensing type")
                asa.create_instance_tags('ASAvLicenseStatus', 'LICENSED')
                return 'SUCCESS'
            elif asa.register_smart_license() == 'SUCCESS':
                time.sleep(30)
                if asa.verify_asav_byol_licensed() == 'SUCCESS' and asa.verify_asa_license_authorized() == 'SUCCESS':
                    asa.create_instance_tags('ASAvLicenseStatus', 'LICENSED')
                    return 'SUCCESS'
        time.sleep(30)
    else:
        logger.info("Invalid user input for ASAv License Type")

    return 'FAIL'

def execute_cluster_delete_first(asa):
    """
    Purpose:    This deletes the instance from AutoScale Group
    Parameters: Object of ASAvInstance class
    Returns:    SUCCESS, FAIL
    Raises:
    """
    try:
        state = asa.get_instance_state()
        if state != 'terminated':
            asg_removal_status = asa.asg.remove_instance(asa.instance_id, const.DECREMENT_CAP_IF_CLUSTER_DELETED)
            if asg_removal_status is not None:
                raise Exception("Unable to delete Instance from ASG ")
        return 'SUCCESS'
    except Exception as e:
        logger.error("Exception occurred {}".format(e))
        return 'FAIL'

def execute_vm_delete_second(asa):
    """
    Purpose:    This runs some job on ASAv while Termination Lifecycle Hook is ON
    Parameters: Object of ASAvInstance class
    Returns:    SUCCESS, FAIL
    Raises:
    """
    try:
        state = asa.get_instance_state()
        if state != 'terminated':
            license_dereg_status = asa.deregister_smart_license()
            if license_dereg_status == 'FAILURE':
                raise Exception("Unable to de-register smart license ")
        return 'SUCCESS'
    except Exception as e:
        logger.error("Exception occurred {}".format(e))
        return 'FAIL'

def verify_cluster_status(aws_grp, asa):
    """
    Purpose:    Verify cluster formation status
    Parameters: Object of AutoscaleGroup and ASAvInstance class
    Returns:    SUCCESS, FAIL
    Raises:
    """
    des, mins, maxs = aws_grp.get_asgroup_size()
    logger.info("Cluster Group Size: {}".format(mins))
    try:
        if mins != 1:
            count=0
            while count<5:
                status = asa.cluster_status()
                members = status.count('DATA_NODE')
                if members is (mins - 1):
                    break
                logger.info("Waiting for cluster to be formed..")
                logger.info("Number of Data node joined: {}".format(members))
                time.sleep(30)
                count+=1
            status = asa.cluster_status()
            control = status.count('CONTROL_NODE')
            members = status.count('DATA_NODE')
            logger.info(status)
            if (control != 1 and members != (mins - 1)) or count == 3:
                logger.info('Cluster is not properly formed..!!')
                asa.create_instance_tags('ClusterStatus', 'NOT FORMED')
                return 'FAIL'
            logger.info("Control node: {}".format(control))
            logger.info("Data nodes: {}".format(members))
            asa.create_instance_tags('ClusterStatus', 'FORMED')
            return "SUCCESS"
        else:
            count=0
            while count<5:
                status = asa.cluster_status()
                if "CONTROL_NODE" in status:
                    break
                logger.info("Waiting for cluster to be formed..")
                time.sleep(30)
                count+=1
            if count == 5:
                logger.info('Cluster is not properly formed..!!')
                asa.create_instance_tags('ClusterStatus', 'NOT FORMED')
                return 'FAIL'
            status = asa.cluster_status()
            logger.info(status)
            asa.create_instance_tags('ClusterStatus', 'FORMED')
            return "SUCCESS"
    except Exception as e:
        logger.error("Exception occurred {}".format(e))
        asa.create_instance_tags('ClusterStatus', 'NOT FORMED')
        return 'FAIL'
        
def aws_asg_cls_init():
    """
    Purpose:    To instantiate ClusterGroup class
    Parameters:
    Returns:    Object
    Raises:
    """
    # AWS Cluster Class initialization
    aws_grp = AutoScaleGroup(user_input['AutoScaleGrpName'])
    return aws_grp
