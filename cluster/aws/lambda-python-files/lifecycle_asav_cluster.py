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

Name:       lifecycle.py
Purpose:    This python file has Lambda handler for LifeCycle Lambda
"""

import time
from aws import *
from datetime import datetime, timedelta
from decimal import Decimal
import constant as const
import utility as utl

# Setup Logging
logger = utl.setup_logging(os.environ['DEBUG_LOGS'])
# Get User input
user_input = utl.get_user_input_lifecycle_asav()
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(user_input['AutoScaleGrpName'] + '-lock')

LOCK_ID = "shared-task-lock"
LOCK_TIMEOUT = 120  # seconds
POLL_INTERVAL = 2  # seconds

# LifeCycle Hook Handler
def lambda_handler(event, context):
    """
    Purpose:    Life Cycle Lambda, to attach interfaces to ASAv
    Parameters: AWS Events (CloudWatch)
    Returns:
    Raises:
    """
    utl.put_line_in_log('LifeCycle Lambda Handler started', 'thick')
    logger.info("Received event: " + json.dumps(event, separators=(',', ':')))

    if const.DISABLE_LIFECYCLE_LAMBDA is True:
        logger.info("LifeCycleASAvLambda running is disabled! Check constant.py")
        utl.put_line_in_log('LifeCycle Lambda Handler finished', 'thick')
        return

    life_cycle_action = 'FAIL'

    # EC2 Lifecycle Action
    try:
        instance_id = event['detail']['EC2InstanceId']
        # Initialize class CiscoEc2Instance
        ec2_instance = CiscoEc2Instance(instance_id)

        lifecycle_hookname = event['detail']['LifecycleHookName']
        autoscaling_group_name = event['detail']['AutoScalingGroupName']
        logger.info("Cloud Watch Event Triggered for group {}".format(autoscaling_group_name))
        if autoscaling_group_name != user_input['AutoScaleGrpName']:
            raise ValueError("AutoScale Group name from event & user input doesn't match!")
        # Only assign node ID for valid lifecycle events
        logger.info("udapatil - Number of AZs")
        logger.info(user_input['NO_OF_AZs'])
        if user_input['NO_OF_AZs'] != "1":
            if event["detail-type"] == "EC2 Instance-launch Lifecycle Action":
                start = time.time()
                while not acquire_lock():
                    if time.time() - start > LOCK_TIMEOUT:
                        raise Exception("Timeout waiting for lock.")
                    time.sleep(POLL_INTERVAL)
                if update_nodeid_tag(instance_id) != 'SUCCESS':
                    release_lock()
                    raise ValueError("Node ID is not assigned to Instance")
                release_lock()
    except KeyError as e:
        logger.debug("Error occurred: {}".format(repr(e)))
        logger.info("Not an EC2 Lifecycle CloudWatch event!")
        pass
    except ValueError as e:
        logger.error("Error occurred: {}".format(repr(e)))
        pass
    else:
        if event["detail-type"] == "EC2 Instance-launch Lifecycle Action":
            if const.DISABLE_CREATE_ATTACH_INT is False:
                create_tags_with_default_values(ec2_instance)  # Create Default Tags on Instance
                ec2_instance.disable_src_dst_check_on_primary_int() # Modify src/dst check
                if create_interface_and_attach(ec2_instance) == 'SUCCESS':
                    if const.DISABLE_REGISTER_TARGET is False:
                        if register_instance(ec2_instance) == 'SUCCESS':
                            ec2_instance.lb.modify_target_groups_deregistration_delay(
                                user_input['GWLB_ARN'], user_input['LB_DEREGISTRATION_DELAY'])
                            life_cycle_action = 'SUCCESS'
                    else:
                        logger.info("register_instance function is disabled! Check constant.py")
            else:
                logger.info("create_interface_and_attach function is disabled! Check constant.py")

        elif event["detail-type"] == "EC2 Instance-terminate Lifecycle Action":
            state = ec2_instance.get_instance_state()
            if state != 'terminated' or state is not None:
                # Run 'license smart deregister' from ConfigureASAv Lambda
                lifecycle_deregister_smart_license(instance_id)
                if deregister_instance(ec2_instance) == 'SUCCESS':
                    time.sleep(int(user_input['LB_DEREGISTRATION_DELAY']))
                    if user_input['PROXY_TYPE'] == 'dual-arm':
                        if disassociate_and_release_eip(ec2_instance) != 'SUCCESS':
                            life_cycle_action = 'FAIL'
                    life_cycle_action = 'SUCCESS'
                else:
                    life_cycle_action = 'FAIL'
            else:
                logger.info("Instance is already Terminated or No valid State found")
                life_cycle_action = 'SUCCESS'

        else:
            logger.error("Not a EC2 Instance Lifecycle Action")

        if life_cycle_action == 'SUCCESS':
            ec2_instance.asg.complete_lifecycle_action_success(lifecycle_hookname, instance_id)
        else:
            ec2_instance.asg.complete_lifecycle_action_failure(lifecycle_hookname, instance_id)

    utl.put_line_in_log('LifeCycle Lambda Handler finished', 'thick')
    return

def acquire_lock():
    try:
        table.put_item(
            Item={
                "lock_id": LOCK_ID,
                "timestamp": Decimal(str(time.time()))
            },
            ConditionExpression="attribute_not_exists(lock_id)"
        )
        print("Lock acquired.")
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            print("Lock is already held.")
            return False
        else:
            raise

def release_lock():
    table.delete_item(Key={"lock_id": LOCK_ID})
    print("Lock released.")

def update_nodeid_tag(instance_id):
    # Assign a unique nodeID tag to this instance
    # Use EC2Instance directly to avoid potential circular import issues
    ec2_instance = EC2Instance(instance_id)
    node_id = ec2_instance.assign_cls_node_id_tag()
    if node_id is not None:
        logger.info(f"Assigned nodeID {node_id} to instance {instance_id}")
        return 'SUCCESS'
    else:
        logger.warning(f"Failed to assign nodeID to instance {instance_id}")
        return 'FAIL'

def create_interface_and_attach(ec2_instance):
    """
    Purpose:    This creates, attaches interfaces to ASAv
    Parameters: Instance Id
    Returns:    SUCCESS, FAIL
    Raises:
    """
    user_input = utl.get_user_input_lifecycle_asav()
    # Get Availability zone & Subnet
    instance_az = ec2_instance.get_instance_az()
    logger.info("EC2 instance has been launched in AZ: " + instance_az)
    subnets_list_in_az = ec2_instance.get_subnet_list_in_az(instance_az)
    logger.info("List of subnet in %s is: %s" % (instance_az, subnets_list_in_az))
    if user_input['PROXY_TYPE'] != 'dual-arm':
        user_input['max_number_of_interfaces'] = '2'
    # Create and Attach interfaces from respective subnet
    utl.put_line_in_log('Attaching Interface', 'dot')

    # Should be able to add defined max no of interfaces
    for dev_index in range(1, int(user_input['max_number_of_interfaces'])+1):
        if dev_index == 2 and user_input['PROXY_TYPE'] != 'dual-arm':
            logger.info("Single-arm deployment mode!")
            user_input['SUBNET_ID_LIST_2'] = user_input['SUBNET_ID_LIST_3']
            user_input['SECURITY_GRP_2'] = user_input['SECURITY_GRP_3']
        eni_name = ec2_instance.instance_id + const.ENI_NAME_PREFIX + str(dev_index)
        sec_grp_id = user_input[const.SECURITY_GROUP_PREFIX + str(dev_index)]
        subnet_id_list = const.SUBNET_ID_LIST_PREFIX + str(dev_index)
        # User should have given only one subnet id from this availability zone
        subnet_id = utl.get_common_member_in_list(subnets_list_in_az, user_input[subnet_id_list])
        if len(subnet_id) > 1:
            logger.error("For interface %s, more than one subnet found from an availability zone!" % eni_name)
            logger.error(subnet_id)
            return 'FAIL'
        elif len(subnet_id) < 1:
            logger.error("For interface %s, less than one subnet found from an availability zone!" % eni_name)
            logger.error(subnet_id)
            return 'FAIL'
        # Create interface in the subnet with security group
        interface_id = ec2_instance.create_interface(str(subnet_id[0]), sec_grp_id, eni_name)

        if interface_id:
            # Attach interface to instance with device index
            attachment, err = ec2_instance.attach_interface(interface_id, dev_index)
            if not attachment:
                ec2_instance.delete_interface(interface_id)
                if len(re.findall('already has an interface attached at', str(err))) >= 1:
                    logger.warn("Already has an attached network interface at device index: %s" % str(dev_index))
                    pass
                utl.put_line_in_log('Attaching Interface: FAILED', 'dot')
                return 'FAIL'
        else:
            utl.put_line_in_log('Attaching Interface: FAILED', 'dot')
            return 'FAIL'
    return 'SUCCESS'


def register_instance(ec2_instance):
    """
    Purpose:    To register Gig0/1 IP to Load Balancer
    Parameters: Object
    Returns:    SUCCESS, FAIL
    Raises:
    """
    utl.put_line_in_log('Registering inside interface to Target Groups', 'dot')
    eni_name = ec2_instance.instance_id + const.ENI_NAME_PREFIX + str(1)

    if ec2_instance.register_instance_to_lb(user_input['GWLB_ARN'], eni_name) == 'FAIL':
        utl.put_line_in_log('Registering to Target Groups: FAILED', 'dot')
        return 'FAIL'
    utl.put_line_in_log('Registering to Target Groups: SUCCESS', 'dot')
    return 'SUCCESS'


def deregister_instance(ec2_instance):
    """
    Purpose:    To de-register Gig0/1 IP from LB
    Parameters: Instance Id
    Returns:    SUCCESS, FAIL
    Raises:
    """
    utl.put_line_in_log('De-registering inside interface from Target Groups', 'dot')
    eni_name = ec2_instance.instance_id + const.ENI_NAME_PREFIX + str(1)

    if ec2_instance.deregister_instance_from_lb(user_input['GWLB_ARN'], eni_name) == 'FAIL':
        utl.put_line_in_log('De-registering from Target Groups finished: FAIL', 'dot')
        return 'FAIL'
    utl.put_line_in_log('De-registering from Target Groups finished: SUCCESS', 'dot')
    return 'SUCCESS'


def create_tags_with_default_values(ec2_instance):
    """
    Purpose:    To create tags on EC2 instance
    Parameters: EC2Instance object
    Returns:
    Raises:
    """
    ec2_instance.create_instance_tags('ASAvConfigurationStatus', 'PENDING')
    ec2_instance.create_instance_tags('ASAvConnectionStatus', 'UN-AVAILABLE')

    if user_input['ASA_LICENSE_TYPE'] == 'PAYG':
        ec2_instance.create_instance_tags('ASAvLicenseType', 'PAYG')
    elif user_input['ASA_LICENSE_TYPE'] == 'BYOL':
        ec2_instance.create_instance_tags('ASAvLicenseType', 'BYOL')
    else:
        ec2_instance.create_instance_tags('ASAvLicenseType', 'IN-VALID')
    return 'SUCCESS'


def lifecycle_deregister_smart_license(instance_id):
    """
    Purpose:    To deregister license of ASAv instance, This function creates link to ConfigureASAv Lambda
    Parameters: instance_id,
    Returns:    None
    Raises:
    """
    # SNS class initialization
    sns = SimpleNotificationService()
    message_subject = 'EVENT: ' + user_input['AutoScaleGrpName'] + ' ' + 'instance deregister' + ' ' + \
                      instance_id
    msg_body = utl.sns_msg_body_configure_asav_topic('ASAv De-register smart license', 'cluster_delete', 'SECOND',
                                                     instance_id)
    sns.publish_to_topic(user_input['CLS_MANAGER_TOPIC'], message_subject, msg_body)
    # Sleep for 90 seconds
    time.sleep(1 * 90)  # Will be covered in Deregistration delay in future
    return

def disassociate_and_release_eip(ec2_instance):
    """
    Purpose:    To disassociate and release EIP associated with Gig0/1 interface for Dual-arm
    Parameters: Object
    Returns:    SUCCESS, FAIL
    Raises:
    """
    utl.put_line_in_log('Disassociating and Releasing Elastic IP for outside interface', 'dot')
    if ec2_instance.disassociate_from_instance_and_release_eip() == 'FAIL':
        utl.put_line_in_log('Disassociating and Releasing Elastic IP for outside interface: FAIL', 'dot')
