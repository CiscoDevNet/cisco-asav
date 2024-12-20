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

Name:       aws.py
Purpose:    This python file has AWS related class & methods
            These classes will be initialized in Lambda function as needed
"""

import boto3
import botocore
import json
import os
import time
import re
import ipaddress
from botocore.exceptions import ClientError
import constant as const
import utility as utl

# Setup Logging
logger = utl.setup_logging(os.environ['DEBUG_LOGS'])


class SimpleNotificationService:
    """
        This is SimpleNotificationService class for AWS SNS services
    """
    def __init__(self):
        self.sns_client = boto3.client('sns')

    def publish_to_topic(self, topic_arn, subject, sns_message):
        """
        Purpose:    Publish message to SNS Topic
        Parameters: Topic ARN, Message Body, Subject, to_function, category, instance_id, counter
        Returns:    Response of Message publish
        Raises:     None
        """
        sns_message_default = json.dumps(sns_message, sort_keys=True, indent=4, separators=(',', ': '))
        sns_message_email = json.dumps(sns_message, sort_keys=True, indent=4, separators=(',', ': '))

        message = {
            "default": sns_message_default,
            "email": sns_message_email
        }

        logger.debug("Publishing Message: " + json.dumps(message, separators=(',', ':')))

        try:
            response = self.sns_client.publish(
                TopicArn=topic_arn,
                Message=json.dumps(message),
                MessageStructure='json',
                Subject=subject
                )
            return response
        except Exception as e:
            logger.critical("Error occurred: {}".format(repr(e)))
            logger.error("Unable to publish message to SNS Topic: %s" % topic_arn)


class AutoScaleGroup:
    """
        This is AutoScaleGroup class for AWS AutoScale group methods
    """
    def __init__(self, groupname):
        self.groupname = groupname
        self.asg_client = boto3.client('autoscaling')

    def remove_instance(self, instance_id, decrement_cap=True):
        """
        Purpose:    To remove instance from AutoScale Group
        Parameters: Instance id, DecrementCapacity
        Returns:    Boto3 response
        Raises:
        """
        try:
            response = self.asg_client.terminate_instance_in_auto_scaling_group(
                InstanceId=instance_id,
                ShouldDecrementDesiredCapacity=decrement_cap
            )
        except botocore.exceptions.ClientError as e:
            logger.error("Botocore Error removing the instance: {}".format(e.response['Error']))
            return None
        except Exception as e:
            logger.error("General Error removing the instance" + str(e))
            return None
        return response
        
    def get_asgroup_size(self):
        """
        Purpose:        To get Desired, Min and Max AutoScale Group size.
        Parameters:
        Returns:        Desired, Min and Max group size.
        Raises:
        """
        instance_list = []
        try:
            response = self.asg_client.describe_auto_scaling_groups(
                AutoScalingGroupNames=[
                    self.groupname
                ]
            )
            DesiredCapacity = response["AutoScalingGroups"][0]["DesiredCapacity"]
            MinSize = response["AutoScalingGroups"][0]["MinSize"]
            MaxSize = response["AutoScalingGroups"][0]["MaxSize"]
        except botocore.exceptions.ClientError as e:
            logger.error("Botocore Error: {}".format(e.response['Error']))
            return None
        except Exception as e:
            logger.error("General Error getting group size" + str(e))
            return None
        return DesiredCapacity, MinSize, MaxSize

    def complete_lifecycle_action_success(self, hookname, instance_id):
        """
        Purpose:    This will complete lifecycle hook, SUCCESS case
        Parameters: Hookname, Group Name, Instance Id
        Returns:
        Raises:
        """
        try:
            self.asg_client.complete_lifecycle_action(
                    LifecycleHookName=hookname,
                    AutoScalingGroupName=self.groupname,
                    InstanceId=instance_id,
                    LifecycleActionResult='CONTINUE'
            )
            logger.info("Lifecycle hook CONTINUEd for: {}".format(instance_id))
        except botocore.exceptions.ClientError as e:
            logger.error("Error completing life cycle hook for instance {}: {}".format(instance_id,
                                                                                       e.response['Error']))
            if re.findall('No active Lifecycle Action found', str(e)):
                logger.info("Lifecycle hook has already been CONTINUEd")

    def complete_lifecycle_action_failure(self, hookname, instance_id):
        """
        Purpose:    This will complete lifecycle hook, FAIL case
        Parameters: Hookname, Group Name, Instance Id
        Returns:
        Raises:
        """
        try:
            self.asg_client.complete_lifecycle_action(
                    LifecycleHookName=hookname,
                    AutoScalingGroupName=self.groupname,
                    InstanceId=instance_id,
                    LifecycleActionResult='ABANDON'
            )
            logger.info("Lifecycle hook ABANDONed for: {}".format(instance_id))
        except botocore.exceptions.ClientError as e:
            logger.error("Error completing life cycle hook for instance {}: {}".format(instance_id,
                                                                                       e.response['Error']))
            if re.findall('No active Lifecycle Action found', str(e)):
                logger.info("Lifecycle hook has already been CONTINUEd")


class CloudWatch:
    """
        This is CloudWatch class for AWS CloudWatch methods
    """
    def __init__(self):
        self.client = boto3.client('cloudwatch')

    def set_alarm_state(self, alarm_name, state='INSUFFICIENT_DATA'):
        """
        Purpose:    To set alarm state
        Parameters: Alarm Name, state of alarm to be set
        Returns:    Response
        Raises:
        """
        logger.info("Setting alarm %s state to %s " % (alarm_name, state))
        response = self.client.set_alarm_state(
            AlarmName=alarm_name,
            StateValue=state,
            StateReason='Setting state from Lambda',
        )
        return response


class EC2Instance:
    """
        This is EC2Instance class for AWS EC2 methods
    """
    def __init__(self, instance_id):
        self.ec2 = boto3.client('ec2')
        self.instance_id = instance_id

    def __get_describe_instance(self):
        """
        Purpose:    Describe EC2 instance
        Parameters:
        Returns:    Describe response
        Raises:
        """
        try:
            response = self.ec2.describe_instances(
                InstanceIds=[
                    self.instance_id,
                ]
            )
        except ClientError as e:
            logger.error("Unable find describe-instances for instance: " + self.instance_id)
            logger.error(str(e))
            return None
        else:
            return response

    def get_describe_instance_from_private_ip(self, private_ip):
        """
        Purpose:    To get EC2 instance details from a private Ip
        Parameters: Private Ip
        Returns:    Describe Instance response
        Raises:
        """
        try:
            response = self.ec2.describe_instances(
                Filters=[{'Name': 'network-interface.addresses.private-ip-address', 'Values': [private_ip]}]
            )
        except ClientError as e:
            logger.info("Unable find describe-instances for ip: " + private_ip)
            logger.debug(str(e))
            return None
        else:
            return response

    def get_subnet_id_by_interface_name(self, inst_id):
        """
        Purpose:    To get EC2 instance subnet details from an interface name
        Parameters: Instance Id
        Returns:    ccl subnet id of the instance 
        Raises:
        """
        ec2_client = boto3.client('ec2')
        interface_name =  '{}-data-interface-2'.format(inst_id)
        # Describe network interfaces associated with the instance
        response = ec2_client.describe_network_interfaces(Filters=[{'Name': 'attachment.instance-id', 'Values': [inst_id]}])
    
        for network_interface in response['NetworkInterfaces']:
            for tag in network_interface['TagSet']:
                if tag['Key'] == 'Name' and tag['Value'] == interface_name:
                    subnet_id = network_interface['SubnetId']
                    return subnet_id
        return None

    def generate_ccl_route_statements(self, ccl_subnet_ids, curr_ccl_subnet_id):
        """
        Purpose:    To generate ccl route statement for other az subnets
        Parameters: 
        * ccl_subnet_ids - list of ccl subnet ids of other azs
        * curr_ccl_subnet_id - current ccl subnet id 
        Returns:    A list of ccl routes 
        Raises:
        """
        ec2_client = boto3.client('ec2')
        ccl_routes = []
        
        # calculating the current ccl subnet gateway ip
        subnet_response = ec2_client.describe_subnets(SubnetIds=[curr_ccl_subnet_id])
        subnet_cidr = subnet_response['Subnets'][0]['CidrBlock']
        subnet_network = ipaddress.IPv4Network(subnet_cidr)
        curr_ccl_gateway_ip = str(subnet_network.network_address + 1)
        
        # calculating the subnet cidr and subnet mask 
        for subnet_id in ccl_subnet_ids:
            subnet_response = ec2_client.describe_subnets(SubnetIds=[subnet_id])
            subnet_cidr = subnet_response['Subnets'][0]['CidrBlock']
            subnet_network = ipaddress.IPv4Network(subnet_cidr)
            subnet_prefix = str(subnet_network.network_address)
            subnet_mask = str(subnet_network.netmask)
            route_statement = f"route ccl_link {subnet_prefix} {subnet_mask} {curr_ccl_gateway_ip} 1"
            ccl_routes.append(route_statement)
            time.sleep(5)
        return ccl_routes
    
    def get_instance_availability_zone(self, instance_id):
        """
        Purpose:    To retrieve the availability zone of the instance
        Parameters: Instance Id
        Returns:    AvailabilityZone of the instance
        Raises:
        """
        ec2_client = boto3.client('ec2')
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        reservations = response.get('Reservations', [])
        for reservation in reservations:
            instances = reservation.get('Instances', [])
            for instance in instances:
                return instance['Placement']['AvailabilityZone']
        return None


    def get_instance_interfaces_ip(self):
        """
        Purpose:    To get all 4 interfaces IPs
        Parameters:
        Returns:    Dict
                    Example: {'public_ip': '54.88.96.211', 'private_ip': '10.0.250.88', 'inside_ip': '10.0.100.139'}
        Raises:
        """
        interfaces_ip = {}
        response = self.__get_describe_instance()
        try:
            r = response['Reservations'][0]['Instances'][0]['PublicIpAddress']
        except Exception as e:
            logger.debug(str(e))
            interfaces_ip.update({'public_ip': ''})
            pass
        else:
            interfaces_ip.update({'public_ip': r})
        try:
            r = response['Reservations'][0]['Instances'][0]['PrivateIpAddress']
        except Exception as e:
            logger.debug(str(e))
        else:
            interfaces_ip.update({'private_ip': r})

        r = self.get_private_ip_of_interface(const.ENI_NAME_OF_INTERFACE_1)
        if r is not None:
            interfaces_ip.update({'inside_ip1': r})
        else:
            return None

        logger.debug("Retrieved Interfaces IP " + str(interfaces_ip))
        return interfaces_ip

    def get_public_ip(self):
        """
        Purpose:    To get public ip of the host
        Parameters:
        Returns:    Public Ip
        Raises:
        """
        r = None
        response = self.__get_describe_instance()
        try:
            r = response['Reservations'][0]['Instances'][0]['PublicIpAddress']
        except Exception as e:
            logger.debug(str(e))
            return None
        return r

    def get_private_ip(self):
        """
        Purpose:    To get private ip of the host
        Parameters:
        Returns:    Public Ip
        Raises:
        """
        r = None
        response = self.__get_describe_instance()
        try:
            r = response['Reservations'][0]['Instances'][0]['PrivateIpAddress']
        except Exception as e:
            logger.debug(str(e))
            return r
        return r

    def get_instance_state(self):
        """
        Purpose:    To get instance state
        Parameters:
        Returns:    state (running, stopping, stopped, terminated, shutting-down, pending)
        Raises:
        """
        response = self.__get_describe_instance()
        try:
            state = response['Reservations'][0]['Instances'][0]['State']['Name']
            return state
        except Exception as e:
            logger.debug("Unable to get state of %s " % self.instance_id)
            logger.debug("Error occurred: {}".format(repr(e)))
            return None

    def get_instance_asg_name(self):
        """
        Purpose:    To get instance Autoscale Group name
        Parameters:
        Returns:    Autoscale Group name
        Raises:
        """
        asg_name = None
        response = self.__get_describe_instance()
        if response is not None:
            for val in response['Reservations'][0]['Instances'][0]['Tags']:
                if val['Key'] == "aws:autoscaling:groupName":
                    asg_name = str(val['Value'])
                    return asg_name
        else:
            logger.error("Unable to get autoscale group from describe_instance ")
            return asg_name

    def get_instance_tags(self):
        """
        Purpose:    To get instance tags
        Parameters:
        Returns:    Tags in JSON
        Raises:
        """
        response = self.__get_describe_instance()
        if response is not None:
            return response['Reservations'][0]['Instances'][0]['Tags']
        else:
            logger.error("Unable to get autoscale group from describe_instance ")
            return None

    def get_security_group_id(self):
        """
        Purpose:    To get Security group Id
        Parameters: Instance Id
        Returns:
        Raises:
        """
        try:
            result = self.__get_describe_instance()
            sec_grp_id = result['Reservations'][0]['Instances'][0]['SecurityGroups'][0]['GroupId']
            logger.info("Security Group id: {}".format(sec_grp_id))
        except botocore.exceptions.ClientError as e:
            logger.error("Error describing the instance {}: {}".format(self.instance_id, e.response['Error']))
            sec_grp_id = None
        return sec_grp_id

    def get_cidr_describe_subnet(self, subnet_id):
        """
        Purpose:    To get cidr from describe subnet
        Parameters: subnet id
        Returns:    cidr
        Raises:
        """
        try:
            response = self.ec2.describe_subnets(
                Filters=[
                    {
                        'Name': 'subnet-id',
                        'Values': [
                            subnet_id,
                        ]
                    },
                ]
            )
        except ClientError as e:
            logger.info("Unable find describe-subnets for subnet with filter subnet-id: " + subnet_id)
            logger.debug(str(e))
            return None
        else:
            cidr = response['Subnets'][0]['CidrBlock']
            return cidr

    def get_instance_az(self):
        """
        Purpose:    To get AZ of an EC2 Instance
        Parameters: Instance Id
        Returns:    AZ
        Raises:
        """
        r = self.__get_describe_instance()
        if r is not None:
            availability_zone = r['Reservations'][0]['Instances'][0]['Placement']['AvailabilityZone']
            return availability_zone
        else:
            return None

    def get_subnet_list_in_az(self, instance_az):
        """
        Purpose:    To get list of subnets in given AZ
        Parameters: AZ
        Returns:    List of subnets
        Raises:
        """
        subnet_list = []
        r = self.get_describe_subnets_of_az(instance_az)
        if r is not None:
            for item in r['Subnets']:
                subnet_list.append(item['SubnetId'])
            return subnet_list
        else:
            return subnet_list

    def get_describe_subnets_of_az(self, instance_az):
        """
        Purpose:    To get Describe Subnet result in a given Availability zone
        Parameters: Availability Zone
        Returns:    Describe Subnet Response
        Raises:
        """
        try:
            response = self.ec2.describe_subnets(
                Filters=[
                    {
                        'Name': 'availability-zone',
                        'Values': [
                            instance_az,
                        ]
                    },
                ]
            )
        except ClientError as e:
            logger.info("Unable find describe-instances for subnet with filter AZ: " + instance_az)
            logger.debug(str(e))
            return None
        else:
            return response

    def get_private_ip_of_interface(self, interface_suffix):
        """
        Purpose:    To get private ip of a specified interface
        Parameters: Interface suffix
        Returns:    Private Ip
        Raises:
        """
        eni_name = self.instance_id + interface_suffix
        try:
            result = self.ec2.describe_network_interfaces(Filters=[{'Name': 'tag:Name', 'Values': [eni_name]}])
        except Exception as e:
            logger.error("Unable find describe_network_interfaces for instance %s" % self.instance_id)
            logger.error(str(e))
            return
        else:
            try:
                ip = result['NetworkInterfaces'][0]['PrivateIpAddress']
                logger.debug("Private IP of " + eni_name + " interface is {}".format(ip))
                return ip
            except Exception as e:
                logger.error("Unable to get IP from describe_network_interfaces response for interface %s" % eni_name)
                logger.error(str(e))
                return None

    def get_subnet_id_of_interface(self, interface_suffix):
        """
        Purpose:    To get subnet id of interface whose suffix is given
        Parameters: Interface name suffix
        Returns:    subnet id
        Raises:
        """
        eni_name = self.instance_id + interface_suffix
        try:
            result = self.ec2.describe_network_interfaces(Filters=[{'Name': 'tag:Name', 'Values': [eni_name]}])
        except Exception as e:
            logger.error("Unable find describe_network_interfaces for interface %s" % eni_name)
            logger.error(str(e))
            return
        else:
            try:
                subnet_id = result['NetworkInterfaces'][0]['SubnetId']
                logger.debug(subnet_id)
                logger.info("Subnet ID of " + eni_name + " interface is {}".format(subnet_id))
                return subnet_id
            except Exception as e:
                logger.error(
                    "Unable to get subnet_id from describe_network_interfaces response for interface %s" % eni_name)
                logger.error(str(e))
                return None

    def create_interface(self, subnet_id, sec_grp_id, eni_name):
        """
        Purpose:    To create interface in a specified subnet id
        Parameters: Subnet Id, Security Group, ENI name
        Returns:    Interface Id
        Raises:
        """
        network_interface_id = None
        if subnet_id:
            try:
                network_interface = self.ec2.create_network_interface(SubnetId=subnet_id, Groups=[sec_grp_id])
                network_interface_id = network_interface['NetworkInterface']['NetworkInterfaceId']
                logger.info("Created network interface: {}".format(network_interface_id))

                self.ec2.create_tags(Resources=[network_interface_id], Tags=[{'Key': 'Name', 'Value': eni_name}])
                logger.info("Added tag {} to network interface".format(eni_name))
            except botocore.exceptions.ClientError as e:
                logger.error("Error creating network interface: {}".format(e.response['Error']))
        return network_interface_id

    def delete_interface(self, network_interface_id):
        """
        Purpose:    To delete interface
        Parameters: Interface Id
        Returns:
        Raises:
        """
        try:
            self.ec2.delete_network_interface(
                NetworkInterfaceId=network_interface_id
            )
            logger.info("Deleted network interface: {}".format(network_interface_id))
            return True
        except botocore.exceptions.ClientError as e:
            logger.error("Error deleting interface {}: {}".format(network_interface_id, e.response['Error']))

    def attach_interface(self, network_interface_id, device_index):
        """
        Purpose:    To attach interface to device
        Parameters: Network interface id, Instance id, Device index
        Returns:    Attachment
        Raises:
        """
        attachment = None
        if network_interface_id:
            try:
                attach_interface = self.ec2.attach_network_interface(
                    NetworkInterfaceId=network_interface_id,
                    InstanceId=self.instance_id,
                    DeviceIndex=device_index
                )
                attachment = attach_interface['AttachmentId']
                logger.info("Created network attachment: {}".format(attachment))
                try:
                    modify_attachment = self.ec2.modify_network_interface_attribute(
                        Attachment={
                            'AttachmentId': attachment,
                            'DeleteOnTermination': True
                        },
                        # Description={
                        # 	'Value': 'string'
                        # },
                        # DryRun=True|False,
                        # Groups=[
                        # 	'string',
                        # ],
                        NetworkInterfaceId=network_interface_id,
                        # SourceDestCheck={
                        # 	'Value': True|False
                        # }
                    )
                    logger.debug("Response of modify_network_interface_attribute: %s" % str(modify_attachment))
                    # both "Attachment" and "SourceDestCheck" doesn't go together in same function call
                    # hence we need to call "modify_network_interface_attribute" again with "SourceDestCheck"
                    modify_attachment = self.ec2.modify_network_interface_attribute(
                        NetworkInterfaceId=network_interface_id,
                        SourceDestCheck={
                            'Value': False
                        }
                    )
                    logger.debug("Response of modify_network_interface_attribute: %s" % str(modify_attachment))
                except botocore.exceptions.ClientError as e:
                    logger.error("Error modifying network interface: {}".format(e.response['Error']))
                    return attachment, e.response['Error']
            except botocore.exceptions.ClientError as e:
                logger.error("Error attaching network interface: {}".format(e.response['Error']))
                return attachment, e.response['Error']
        return attachment, ''

    def get_private_ip_of_specific_interface(self, eni_name):
        try:
            result = self.ec2.describe_network_interfaces(Filters=[{'Name': 'tag:Name', 'Values': [eni_name]}])
            logger.debug(result)
            private_ip = result['NetworkInterfaces'][0]['PrivateIpAddress']
        except ClientError as e:
            logger.info("Unable find private IP for eni: %s " % eni_name)
            logger.debug(str(e))
            return None
        except Exception as e:
            logger.debug("Exception {}".format(repr(e)))
            return None
        else:
            return private_ip

    def create_instance_tags(self, tag_name, tag_value):
        """
        Purpose:    To put tag on EC2 instance
        Parameters:
        Returns:    Response
        Raises:
        """
        try:
            response = self.ec2.create_tags(
                Resources=[
                    self.instance_id,
                ],
                Tags=[
                    {
                        'Key': tag_name,
                        'Value': tag_value
                    },
                ]
            )
            logger.info("Created tag: %s and assigned value: %s for %s " % (tag_name, tag_value, self.instance_id))
            logger.debug(response)
            return response
        except Exception as e:
            logger.error("Unable to create tag: %s with value: %s for %s " % (tag_name, tag_value, self.instance_id))
            logger.debug(str(e))
            return None

    def disable_src_dst_check_on_primary_int(self):
        """
        Purpose:    To modify source/destination check on primary interface
        Parameters:
        Returns:    None
        Raises:
        """
        try:
            response = self.ec2.modify_instance_attribute(
                SourceDestCheck={
                    'Value': False
                },
                InstanceId=self.instance_id
            )
            logger.info("Disabled source and destination check on primary interface")
            logger.debug(response)
            return response
        except Exception as e:
            logger.error("Unable to disable source and destination check on primary interface ")
            logger.debug(str(e))
            return None


class ElasticLoadBalancer:
    """
        This ElasticLoadBalancer class is for AWS LB methods
    """
    def __init__(self):
        self.ec2_elb_client = boto3.client('elbv2')

    def __get_targets_health(self, lb_arn):
        """
        Purpose:    To get describe target health on LB
        Parameters: LB ARN
        Returns:    Response
        Raises:
        """
        tg_arn, ports = self.__get_tg_arn_and_port_list(lb_arn)
        try:
            response = self.ec2_elb_client.describe_target_health(
                TargetGroupArn=tg_arn,
            )
        except botocore.exceptions.ClientError as e:
            logger.error("Error describe_target_health: {}".format(e.response['Error']))
            return None
        else:
            return response

    def __get_tg_arn_and_port_list(self, lb_arn):
        """
        Purpose:    To get TGs' ARNs and Ports associated to them in give LB
        Parameters: LB ARN
        Returns:    TG's ARN list, Ports list
        Raises:
        """
        tg_arn = []
        ports = []
        if lb_arn:
            try:
                response = self.ec2_elb_client.describe_target_groups(
                    LoadBalancerArn=lb_arn,
                )
            except botocore.exceptions.ClientError as e:
                logger.error("Error describing target group attributes: {}".format(e.response['Error']))
                return None
            else:
                list_len = len(response['TargetGroups'])
                for i in range(0, list_len):
                    tg_arn.append(response['TargetGroups'][i]['TargetGroupArn'])
                    ports.append(response['TargetGroups'][i]['Port'])
                return tg_arn, ports
        return None

    def register_ip_target_to_lb(self, lb_arn, ip):
        """
        Purpose:    To register an IP target to LB/Target Groups
        Parameters: LB ARN, IP
        Returns:    TG ARNs list
        Raises:
        """
        tg_arns, ports = self.__get_tg_arn_and_port_list(lb_arn)
        if tg_arns is not None:
            list_len = len(tg_arns)
            for i in range(0, list_len):
                try:
                    response = self.ec2_elb_client.register_targets(
                        TargetGroupArn=tg_arns[i],
                        Targets=[
                            {
                                'Id': ip,
                                'Port': ports[i]
                            }
                        ]
                    )
                except botocore.exceptions.ClientError as e:
                    logger.error("Error describe_target_health: {}".format(e.response['Error']))
                    return None
                else:
                    logger.debug(response)
            return tg_arns
        return None

    def deregister_ip_target_from_lb(self, lb_arn, ip):
        """
        Purpose:    To de-register an ip target from LB ARN
        Parameters: LB ARN, IP
        Returns:    TG ARNs list
        Raises:
        """
        tg_arns, ports = self.__get_tg_arn_and_port_list(lb_arn)
        if tg_arns is not None:
            list_len = len(tg_arns)
            for i in range(0, list_len):
                try:
                    response = self.ec2_elb_client.deregister_targets(
                        TargetGroupArn=tg_arns[i],
                        Targets=[
                            {
                                'Id': ip,
                                'Port': ports[i]
                            }

                        ]
                    )
                except botocore.exceptions.ClientError as e:
                    logger.error("Error de-registering the target: {}".format(e.response['Error']))
                else:
                    logger.debug(response)
            return tg_arns
        return None

    def get_unhealthy_ip_targets(self, lb_arn):
        """
        Purpose:    To get list of unhealthy IP targets from LB
        Parameters: LB ARN
        Returns:    list of unhealthy IP targets from all Target Groups of given LB
        Raises:
        """
        unhealthy_ip_targets = []
        tg_arns, ports = self.__get_tg_arn_and_port_list(lb_arn)
        if tg_arns is not None:
            list_len = len(tg_arns)
            for i in range(0, list_len):
                try:
                    response = self.ec2_elb_client.describe_target_health(
                        TargetGroupArn=tg_arns[i],
                    )
                except botocore.exceptions.ClientError as e:
                    logger.error("Error describe_target_health: {}".format(e.response['Error']))
                    return None
                list_len = len(response['TargetHealthDescriptions'])
                if list_len > 0:
                    for j in range(0, list_len):
                        target = response['TargetHealthDescriptions'][j]
                        if target['TargetHealth']['State'] == 'unhealthy':
                            # Remove duplicate entries
                            if target['Target']['Id'] not in unhealthy_ip_targets:
                                unhealthy_ip_targets.append(target['Target']['Id'])
            return unhealthy_ip_targets
        return None

    def modify_target_groups_deregistration_delay(self, lb_arn, dereg_delay):
        """
        Purpose:    To modify de-registration delay on LB
        Parameters: LB ARN, dereg delay in seconds
        Returns:    Response
        Raises:
        """
        tg_arns, ports = self.__get_tg_arn_and_port_list(lb_arn)
        if tg_arns is not None:
            list_len = len(tg_arns)
            for i in range(0, list_len):
                try:
                    response = self.ec2_elb_client.modify_target_group_attributes(
                        TargetGroupArn=tg_arns[i],
                        Attributes=[
                            {
                                'Key': 'deregistration_delay.timeout_seconds',
                                'Value': str(dereg_delay),
                            },
                        ]
                    )
                except botocore.exceptions.ClientError as e:
                    logger.error("Error modifying target group attributes: {}".format(e.response['Error']))
                    return None
                else:
                    logger.debug("Modifying TG: %s deregistration delay" % tg_arns[i])
                    logger.debug(response)
            return tg_arns
        return None


class CiscoEc2Instance(EC2Instance):
    """
        This CiscoEc2Instance class is child class of EC2Instance
    """
    def __init__(self, instance_id, group=None):
        super().__init__(instance_id)
        if group is None:
            group = super().get_instance_asg_name()
            self.asg = AutoScaleGroup(group)
        self.vm_name = group + '-' + self.instance_id
        self.lb = ElasticLoadBalancer()
        self.SUCCESS = 'SUCCESS'
        self.FAIL = 'FAIL'

    def register_instance_to_lb(self, lb_arn, eni_name):
        """
        Purpose:    To register a specific instance interface to LB
        Parameters: LB ARN, ENI name
        Returns:    FAIL or SUCCESS
        Raises:
        """
        try:
            private_ip = self.get_private_ip_of_specific_interface(eni_name)
            if private_ip is None:
                logger.error("Unable to find private IP address for interface")
                return self.FAIL
            logger.info("Private IP of interface: {}".format(private_ip))
            if self.lb.register_ip_target_to_lb(lb_arn, private_ip) is None:
                logger.error("Unable to register %s to Load Balancer" % private_ip)
        except botocore.exceptions.ClientError as e:
            logger.error("Error registering the target: {}".format(e.response['Error']))
            return self.FAIL
        else:
            return self.SUCCESS

    def deregister_instance_from_lb(self, lb_arn, eni_name):
        """
        Purpose:    To de-register a specific instance interface from LB
        Parameters: LB ARN, ENI name
        Returns:    FAIL or SUCCESS
        Raises:
        """
        try:
            private_ip = self.get_private_ip_of_specific_interface(eni_name)
            if private_ip is None:
                logger.error("Unable to find private IP address for interface")
                return self.FAIL
            logger.info("Private IP of interface: {}".format(private_ip))
            if self.lb.deregister_ip_target_from_lb(lb_arn, private_ip) is None:
                logger.error("Unable to deregister %s from Load Balancer" % private_ip)
        except botocore.exceptions.ClientError as e:
            logger.error("Error de-registering the target: {}".format(e.response['Error']))
            return self.FAIL
        else:
            return self.SUCCESS
