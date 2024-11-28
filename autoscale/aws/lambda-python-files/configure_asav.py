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
        logger.info("Received an event but not an SNS notification event")
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
            if sns_msg_attr['NewStateValue'] == 'ALARM' and \
                    sns_msg_attr["Trigger"]['MetricName'] == 'UnHealthyHostCount':
                execute_instance_tg_health_doctor()
                # Set the alarm to 'INSUFFICIENT_DATA' or 'OK'
                cloud_watch_client = CloudWatch()
                cloud_watch_client.set_alarm_state(sns_msg_attr['AlarmName'], 'INSUFFICIENT_DATA')
            utl.put_line_in_log('SNS Handler finished', 'thin')
            return
        except KeyError as e:
            logger.debug("Exception occurred {}".format(repr(e)))

    try: # Exception-handling for cases where function counter <= 0
        if sns_msg_attr['instance_id'] is None:
            logger.critical("Received instance_id None!")
            utl.put_line_in_log('SNS Handler Finished', 'thin')
            return
        if int(sns_msg_attr['counter']) <= 0 and sns_msg_attr['to_function'] != 'vm_delete':
            logger.critical("Function %s has run out of retries !!  Calling vm_delete...", sns_msg_attr['to_function'])
            if not const.DISABLE_VM_DELETE_FUNC:
                message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + 'instance delete' + ' ' + \
                                  sns_msg_attr['instance_id']
                msg_body = utl.sns_msg_body_configure_asav_topic('VM not accessible', 'vm_delete', 'FIRST',
                                                                 sns_msg_attr['instance_id'])
                sns.publish_to_topic(user_input['ConfigureASAvTopic'], message_subject, msg_body)
            else:
                logger.info(" vm_delete function is disabled! Check constant.py")
            utl.put_line_in_log('SNS Handler Finished', 'thin')
            return
        elif int(sns_msg_attr['counter']) <= 0 and sns_msg_attr['to_function'] == 'vm_delete':
            logger.critical("Unable to delete device %s" % sns_msg_attr['instance_id'])
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

    #Checking instance state is running / pending for functions 'vm_ready' , 'vm_configure' , 'vm_license'
    if sns_msg_attr['to_function'] == 'vm_delete':
        pass
    elif instance_state == 'running' or instance_state == 'pending':
        pass
    else:
        logger.error("Device in %s state, can't be handled by %s function"
                     % (instance_state, sns_msg_attr['to_function']))
        utl.put_line_in_log('SNS Handler Finished', 'thin')
        return

    logger.info("Continue to execute action of " + sns_msg_attr['to_function'])

    if sns_msg_attr['to_function'] == 'vm_ready':
        if const.DISABLE_VM_READY_FUNC is True:
            logger.info(sns_msg_attr['to_function'] + " function is disabled! Check constant.py")
            utl.put_line_in_log('SNS Handler Finished', 'thin')
            return
        asa.create_instance_tags('Name', asa.vm_name)  # To put Name tag on instance
        if sns_msg_attr['category'] == 'FIRST':
            if execute_vm_ready_first(asa) == 'SUCCESS':
                logger.info("SSH to ASAv is successful, Next action: Configuration")
                if not const.DISABLE_VM_CONFIGURE_FUNC:
                    message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + 'instance configure' + ' ' + \
                                      sns_msg_attr['instance_id']
                    msg_body = utl.sns_msg_body_configure_asav_topic('VM is ready', 'vm_configure',  'FIRST',
                                                                     sns_msg_attr['instance_id'])
                    sns.publish_to_topic(user_input['ConfigureASAvTopic'], message_subject, msg_body)
                else:
                    logger.info(" vm_configure function is disabled! Check constant.py")
            else:
                logger.warn("SSH to ASAv with instance_id: %s is un-successful, Retrying..." %
                            sns_msg_attr['instance_id'])
                message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + 'instance poll' + ' ' + \
                                  sns_msg_attr['instance_id']
                msg_body = utl.sns_msg_body_configure_asav_topic('Check VM is ready', 'vm_ready', 'FIRST',
                                                                 sns_msg_attr['instance_id'],
                                                                 str(int(sns_msg_attr['counter']) - 1))
                sns.publish_to_topic(user_input['ConfigureASAvTopic'], message_subject, msg_body)

    elif sns_msg_attr['to_function'] == 'vm_configure':
        if const.DISABLE_VM_CONFIGURE_FUNC is True:
            logger.info(sns_msg_attr['to_function'] + " function is disabled! Check constant.py")
            utl.put_line_in_log('SNS Handler Finished', 'thin')
            return
        if sns_msg_attr['category'] == 'FIRST':
            if execute_vm_configure_first(asa) == 'SUCCESS':
                if not const.DISABLE_LICENSE_VERIFIER_FUNC:
                    logger.info("Configuration of ASAv is successful, Next action: Licensing")
                    message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + 'instance license' + ' ' + \
                                      sns_msg_attr['instance_id']
                    msg_body = utl.sns_msg_body_configure_asav_topic('VM is configured', 'vm_license',  'FIRST',
                                                                     sns_msg_attr['instance_id'])
                    sns.publish_to_topic(user_input['ConfigureASAvTopic'], message_subject, msg_body)
                else:
                    logger.info(" vm_license function is disabled! Check constant.py")
                if user_input['USER_NOTIFY_TOPIC_ARN'] is not None:
                    # Email to user
                    details_of_the_device = json.dumps(asa.get_instance_tags())
                    message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + \
                                      sns_msg_attr['instance_id'] + ' ' + 'instance configured'
                    msg_body = utl.sns_msg_body_user_notify_topic('VM Configured', user_input['AutoScaleGrpName'],
                                                                  sns_msg_attr['instance_id'], details_of_the_device)
                    sns.publish_to_topic(user_input['USER_NOTIFY_TOPIC_ARN'], message_subject, msg_body)
                    # -------------
            else:
                logger.warn("Configuration failed! trying again in next cycle...")
                message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + 'instance configure' + ' ' + \
                                  sns_msg_attr['instance_id']
                msg_body = utl.sns_msg_body_configure_asav_topic('VM not configured', 'vm_configure', 'FIRST',
                                                                 sns_msg_attr['instance_id'],
                                                                 str(int(sns_msg_attr['counter']) - 1))
                sns.publish_to_topic(user_input['ConfigureASAvTopic'], message_subject, msg_body)

    elif sns_msg_attr['to_function'] == 'vm_license':
        if const.DISABLE_LICENSE_VERIFIER_FUNC is True:
            logger.info(sns_msg_attr['to_function'] + " function is disabled! Check constant.py")
            utl.put_line_in_log('SNS Handler Finished', 'thin')
            return
        if sns_msg_attr['category'] == 'FIRST':
            if execute_vm_license_first(asa) == 'SUCCESS':
                logger.info("Licensing of ASAv is successful!")
                details_of_the_device = json.dumps(asa.get_instance_tags())
                logger.info(details_of_the_device)
                if user_input['USER_NOTIFY_TOPIC_ARN'] is not None:
                    # Email to user
                    message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + \
                                      sns_msg_attr['instance_id'] + ' ' + 'instance licensed'
                    msg_body = utl.sns_msg_body_user_notify_topic('VM Licensed',
                                                                  user_input['AutoScaleGrpName'],
                                                                  sns_msg_attr['instance_id'], details_of_the_device)
                    sns.publish_to_topic(user_input['USER_NOTIFY_TOPIC_ARN'], message_subject, msg_body)
                    # -------------
            else:
                logger.warn("Licensing failed! trying again in next cycle...")
                message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + 'instance configure' + ' ' + \
                                  sns_msg_attr['instance_id']
                msg_body = utl.sns_msg_body_configure_asav_topic('VM not configured with license', 'vm_license',
                                                                 'FIRST',
                                                                 sns_msg_attr['instance_id'],
                                                                 str(int(sns_msg_attr['counter']) - 1))
                sns.publish_to_topic(user_input['ConfigureASAvTopic'], message_subject, msg_body)

    elif sns_msg_attr['to_function'] == 'vm_delete':
        if sns_msg_attr['category'] == 'FIRST':
            if execute_vm_delete_first(asa) == 'SUCCESS':
                logger.info("Instance has been deleted! ")
            else:
                logger.critical("Unable to delete instance!")
                message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + 'instance delete' + ' ' + \
                                  sns_msg_attr['instance_id']
                msg_body = utl.sns_msg_body_configure_asav_topic('VM not deleted from ASG', 'vm_delete', 'FIRST',
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
                msg_body = utl.sns_msg_body_configure_asav_topic('VM not deleted from ASG', 'vm_delete', 'SECOND',
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
            msg_body = utl.sns_msg_body_configure_asav_topic('Check VM is ready', 'vm_ready', 'FIRST', instance_id)
            sns.publish_to_topic(user_input['ConfigureASAvTopic'], message_subject, msg_body)
        if instance_state == 'running' or instance_state == 'pending':
            logger.info("Instance %s is in state: %s" % (instance_id, instance_state))
            message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + 'instance poll' + ' ' + instance_id
            msg_body = utl.sns_msg_body_configure_asav_topic('Check VM is ready', 'vm_ready', 'FIRST', instance_id)
            sns.publish_to_topic(user_input['ConfigureASAvTopic'], message_subject, msg_body)
        else:
            logger.warn("Instance %s is in state: %s" % (instance_id, instance_state))

        if user_input['USER_NOTIFY_TOPIC_ARN'] is not None:
            # Email to user
            details_of_the_device = None
            message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + instance_id + ' ' + \
                              'instance is launched'
            msg_body = utl.sns_msg_body_user_notify_topic('VM Launched', user_input['AutoScaleGrpName'],
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

        if user_input['USER_NOTIFY_TOPIC_ARN'] is not None:
            # Email to user
            details_of_the_device = None
            message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + instance_id + ' ' + \
                              'instance is terminated'
            msg_body = utl.sns_msg_body_user_notify_topic('VM Terminated', user_input['AutoScaleGrpName'],
                                                          instance_id, details_of_the_device)
            sns.publish_to_topic(user_input['USER_NOTIFY_TOPIC_ARN'], message_subject, msg_body)
            # -------------

    utl.put_line_in_log('EC2 Terminate Handler finished', 'thin')
    return


def execute_vm_ready_first(asa):
    """
    Purpose:    This polls ASAv instance for it's SSH accessibility
    Parameters: Object of type ASAvInstance class
    Returns:    SUCCESS, FAIL
    Raises:
    """
    poll_asav = asa.poll_asav_ssh(const.ASAV_POLL_TIME_IN_MIN_VM_READY)
    if poll_asav == "SUCCESS":
        asa.configure_hostname_with_timeout(const.ASAV_POLL_TIME_IN_MIN_VM_READY)
        asa.create_instance_tags('ASAvConnectionStatus', 'AVAILABLE')
        return 'SUCCESS'
    return 'FAIL'


def execute_vm_configure_first(asa):
    """
    Purpose:    This configures ASAv instance
    Parameters: Object of ASAvInstance class
    Returns:    SUCCESS, FAIL
    Raises:
    """
    # Apply device configuration
    asa.create_instance_tags('ASAvConfigurationStatus', 'ONGOING')
    proxy_to_topology = {
    'dual-arm': 'gwlb-dual-arm',
    'single-arm': 'gwlb-single-arm'
    }
    #Determine the topology type ['nlb', 'gwlb-single-arm' or 'gwlb-dual-arm'] based on GENEVE_SUPPORT and PROXY_TYPE
    if user_input['GENEVE_SUPPORT'] == 'enable':
        topology_type = proxy_to_topology.get(user_input['PROXY_TYPE'])
    elif user_input['GENEVE_SUPPORT'] == 'disable':
        topology_type = 'nlb'

    config_url = utl.make_config_url(asa.get_instance_az(), user_input['AZ_LIST'], user_input['ConfigFileUrl'])
    local_file_name = 'Configuration.txt'
    asav_local_file_path = 'disk0:' + local_file_name

    if asa.run_copy_file_running_config(config_url, asav_local_file_path) == "SUCCESS":
        if asa.verify_configuration_file_copy(local_file_name) == "SUCCESS":
            if (user_input['GENEVE_SUPPORT']=='enable') or (user_input['GENEVE_SUPPORT']=='disable' and asa.verify_at_least_one_nat_policy_present() == "SUCCESS"):
                asa.create_instance_tags('ASAvConfigurationStatus', 'DONE')
                logger.info("Configuration has been applied!")
                return 'SUCCESS'

    asa.create_instance_tags('ASAvConfigurationStatus', 'FAIL')
    logger.info("Configuration hasn't been applied!")
    return 'FAIL'


def execute_vm_license_first(asa):
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
                logger.info("ASAv registered with Smart Licensing !!")
                asa.create_instance_tags('ASAvLicenseStatus', 'LICENSED')
                return 'SUCCESS'
            ## register_smart_license implementable only if license token passed from template
            if user_input['SMART_LIC_TOKEN']:
                if asa.register_smart_license(user_input['SMART_LIC_TOKEN']) == 'SUCCESS': 
                    logger.info('Licensing Commands run , checking if Smart-license registered and authorized')
                    time.sleep(30)
                    if asa.verify_asav_byol_licensed() == 'SUCCESS' and asa.verify_asa_license_authorized() == 'SUCCESS':
                        logger.info("ASAv registered successfully with Smart Licensing !!")
                        asa.create_instance_tags('ASAvLicenseStatus', 'LICENSED')
                        return 'SUCCESS'
        # wait 30 seconds
        time.sleep(30)
    else:
        logger.info("Invalid user input for ASAv License Type")

    return 'FAIL'


def execute_vm_delete_first(asa):
    """
    Purpose:    This deletes the instance from AutoScale Group
    Parameters: Object of ASAvInstance class
    Returns:    SUCCESS, FAIL
    Raises:
    """
    try:
        state = asa.get_instance_state()
        if state != 'terminated':
            asg_removal_status = asa.asg.remove_instance(asa.instance_id, const.DECREMENT_CAP_IF_VM_DELETED)
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


def execute_instance_tg_health_doctor():
    """
    Purpose:    To remove un-healthy instances from TG if satisfies conditions
    Parameters:
    Returns:    SUCCESS, FAIL
    Raises:
    """
    # Initializing ElasticLoadBalancer
    elb_client = ElasticLoadBalancer()
    # Initialize EC2Instance with None
    ec2_client = EC2Instance(None)

    utl.put_line_in_log('Instance Doctor', 'dot')
    asg_name = ''
    now = datetime.now(timezone.utc)
    killable_asa_instance = []
    try:
        unhealthy_ip_targets = elb_client.get_unhealthy_ip_targets(user_input['LB_ARN'])
        # logger.info("IPs: " + str(unhealthy_ip_targets) + " found unhealthy!")
    except Exception as e:
        logger.debug("Exception occurred: {}".format(repr(e)))
        logger.info("Unable to get unhealthy IP targets!")
        return

    try:
        logger.info("IPs: " + str(unhealthy_ip_targets) + " found unhealthy!")
        list_len = len(unhealthy_ip_targets)
        if list_len > 0:
            for i in range(0, list_len):
                try:
                    unhealthy_instance = ec2_client.get_describe_instance_from_private_ip(unhealthy_ip_targets[i])
                    instance = unhealthy_instance['Reservations'][0]['Instances'][0]
                    unhealthy_instance_id = instance['InstanceId']
                except Exception as e:
                    logger.info("Exception occurred {}".format(repr(e)))
                    logger.info("Removing IP: " + str(unhealthy_ip_targets[i]) + " as no associated Instance found!")
                    elb_client.deregister_ip_target_from_lb(user_input['LB_ARN'], unhealthy_ip_targets[i])
                    utl.put_line_in_log('Instance Doctor finished', 'dot')
                    return
                for val in instance['Tags']:
                    if val['Key'] == "aws:autoscaling:groupName":
                        asg_name = str(val['Value'])
                if asg_name == user_input['AutoScaleGrpName']:
                    days = (now - instance['LaunchTime']).days
                    hours = (now - instance['LaunchTime']).seconds / 60 / 60
                    logger.info('%s, %s, %d days %d hours alive' %
                                (unhealthy_instance_id, instance['LaunchTime'].strftime('%Y-%m-%d %H:%M:%S'),
                                 days, hours))
                    if days > const.UNHEALTHY_DAYS_THRESHOLD or hours > const.UNHEALTHY_HOURS_THRESHOLD:
                        killable_asa_instance.append(unhealthy_instance_id)
                else:
                    logger.info(unhealthy_instance_id + " is not part of " + str(user_input['AutoScaleGrpName']))
                    logger.info("Removing IP: " + str(unhealthy_ip_targets[i]) + " as it is not of an ASAv VM!")
                    elb_client.deregister_ip_target_from_lb(user_input['LB_ARN'], unhealthy_ip_targets[i])
                    utl.put_line_in_log('Instance Doctor finished', 'dot')
                    return
    except Exception as e:
        logger.error("Exception occurred: {}".format(repr(e)))
        logger.info("Unable to get unhealthy Instances from IPs!")
        utl.put_line_in_log('Instance Doctor finished', 'dot')
        return

    try:
        logger.info("ASAv instances: " + str(killable_asa_instance) + " found unhealthy for more than threshold!")
        list_len = len(killable_asa_instance)
        if list_len > 0:
            ec2_group = AutoScaleGroup(user_input['AutoScaleGrpName'])
            for i in range(0, list_len):
                response = ec2_group.remove_instance(killable_asa_instance[i],
                                                     const.DECREMENT_CAP_IF_VM_REMOVED_BY_DOCTOR)
                if response is not None:
                    logger.info("Removing instance response: " + str(response))
                else:
                    logger.info("Unable to kill instance: " + str(killable_asa_instance[i]))
    except Exception as e:
        logger.error("Exception occurred: {}".format(repr(e)))
        logger.info("Unable to terminate unhealthy Instances!")
        utl.put_line_in_log('Instance Doctor finished', 'dot')
        return
    utl.put_line_in_log('Instance Doctor finished', 'dot')
    return
