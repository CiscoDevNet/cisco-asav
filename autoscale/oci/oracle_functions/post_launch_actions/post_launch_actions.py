"""
Copyright (c) 2021 Cisco Systems Inc or its affiliates.

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

Name:       post_launch_actions.py
Purpose:    This python file has ASAv related class & methods
            Classes in this python files are being used for
            performing Post-Launch action in OCI ASAv Autoscale.
"""

import io
import json
import logging

import oci
import time
import paramiko
import socket
import base64

from fdk import response

logging.basicConfig(force=True, level="INFO")
logging.getLogger("paramiko").setLevel(logging.WARNING)
logger = logging.getLogger()

class ParamikoSSH:
    """
        This Python class supposed to handle interactive SSH session
    """
    def __init__(self, server, port=22, username='admin', password=None):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.port = port
        self.server = server
        self.username = username
        self.password = password
        self.timeout = 60
        self.SUCCESS = 'SUCCESS'
        self.FAIL = 'FAILURE'
        self.AUTH_EXCEPTION = 'Authentication Exception Occurred'
        self.BAD_HOST_KEY_EXCEPTION = 'Bad Key Exception occurred'
        self.SSH_EXCEPTION = 'SSH Exception Occurred'

    def close(self):
        self.ssh.close()

    def verify_server_ip(self):
        try:
            socket.inet_aton(self.server)
            return self.SUCCESS
        except socket.error as e:
            logger.error("POST LAUNCH ACTION: Exception occurred: {}".format(repr(e)))
            return self.FAIL
        except Exception as e:
            logger.error("POST LAUNCH ACTION: Exception occurred: {}".format(repr(e)))
            return self.FAIL

    def connect(self, username, password):
        """
        Purpose:    Opens a connection to server
        Returns:    Success or failure, if failure then returns specific error
                    self.SUCCESS = 'SUCCESS'
                    self.FAIL = 'FAILURE'
                    self.AUTH_EXCEPTION = 'Authentication Exception Occurred'
                    self.BAD_HOST_KEY_EXCEPTION = 'Bad Key Exception occurred'
                    self.SSH_EXCEPTION = 'SSH Exception Occurred'
        """
        if self.verify_server_ip() == 'FAILURE':
            return self.FAIL
        try:
            self.ssh.connect(self.server, self.port, username, password, timeout=29, banner_timeout=29, auth_timeout=29)
            logger.debug("POST LAUNCH ACTION: Connection to %s on port %s is successful!" % (self.server, self.port))
            return self.SUCCESS
        except paramiko.AuthenticationException as exc:
            logger.warn("POST LAUNCH ACTION: Exception occurred: {}".format(repr(exc)))
            return self.AUTH_EXCEPTION
        except paramiko.BadHostKeyException as exc:
            logger.debug("POST LAUNCH ACTION: Exception occurred: {}".format(repr(exc)))
            return self.BAD_HOST_KEY_EXCEPTION
        except paramiko.SSHException as exc:
            logger.debug("POST LAUNCH ACTION: Exception occurred: {}".format(repr(exc)))
            return self.SSH_EXCEPTION
        except BaseException as exc:
            logger.debug("POST LAUNCH ACTION: Exception occurred: {}".format(repr(exc)))
            return self.FAIL
        except Exception as exc:
            logger.debug("POST LAUNCH ACTION: Unknown Exception: {}".format(repr(exc)))
            return self.FAIL

    def execute_cmd(self, command):
        """
        Purpose:    Performs an interactive shell action
        Parameters: Command
        Returns:    action status, output & error
        """
        if self.connect(self.username, self.password) != self.SUCCESS:
            raise ValueError("POST LAUNCH ACTION: Unable to connect to server")
        try:
            ssh_stdin, ssh_stdout, ssh_stderr = self.ssh.exec_command(command, timeout=60)
        except paramiko.SSHException as exc:
            logger.error("POST LAUNCH ACTION: Exception occurred: {}".format(repr(exc)))
            self.ssh.close()
            return self.FAIL, None, None
        else:
            output = ssh_stdout.readlines()
            error = ssh_stderr.readlines()
            logger.debug('POST LAUNCH ACTION: SSH command output: ' + str(output))
            self.ssh.close()
            return self.SUCCESS, str(output), str(error)

    def invoke_interactive_shell(self):
        """
        Purpose:    Performs an interactive shell action
        Parameters:
        Returns:    a new Channel connected to the remote shell
        """
        try:
            shell = self.ssh.invoke_shell()
        except paramiko.SSHException as exc:
            logger.error("POST LAUNCH ACTION: Exception occurred: {}".format(repr(exc)))
            self.ssh.close()
            return self.FAIL, None
        else:
            return self.SUCCESS, shell

    def handle_interactive_session(self, command_set, username, password):
        """
        Purpose:    Performs an interactive shell action
        Parameters:
            command_set: a dict of set of commands expressed in command & expect values
            Example:
                {
                  "cmd1": [
                    {
                      "command": "configure password",
                      "expect": "Enter current password:"
                    },
                    {
                      "command": "Cisco123789!",
                      "expect": "Enter new password:"
                    },
                    {
                      "command": "Cisco@123123",
                      "expect": "Confirm new password:"
                    },
                    {
                      "command": "Cisco@123123",
                      "expect": "Password Update successful"
                    }
                  ]
                }
        Returns:
        Raises:
            ValueError based on the error
        """
        if self.connect(username, password) != self.SUCCESS:
            raise ValueError("POST LAUNCH ACTION: Unable to connect to server")
        status, shell = self.invoke_interactive_shell()
        if status != self.SUCCESS:
            raise ValueError("POST LAUNCH ACTION: Unable to invoke shell")
        if self.send_cmd_and_wait_for_execution(shell, '\n') is not None:
            for key in command_set:
                set = command_set[key]
                for i in range(0, len(set)):
                    command = set[i]['command'] + '\n'
                    expect = set[i]['expect']
                    if self.send_cmd_and_wait_for_execution(shell, command, expect) is not None:
                        pass
                    else:
                        raise ValueError("POST LAUNCH ACTION: Unable to execute command")
        self.ssh.close()
        return

    def send_cmd_and_wait_for_execution(self, shell, command, wait_string='>'):
        """
        Purpose:    Sends command and waits for string to be received
        Parameters: command, wait_string
        Returns:    rcv_buffer or None
        Raises:
        """
        shell.settimeout(self.timeout)
        rcv_buffer = ''
        try:
            shell.send(command)
            while wait_string not in rcv_buffer:
                rcv_buffer = str(shell.recv(10000).decode("utf-8")) + rcv_buffer
            logger.debug("POST LAUNCH ACTION: Command Output: " + rcv_buffer)
            return rcv_buffer
        except Exception as e:
            logger.error("POST LAUNCH ACTION: Error occurred: {}".format(repr(e)))
            return None

class ASAvInstance:
    """
        This is ASAv class, supposed to instantiated only in Configure_ASAv Lambda function
    """
    def __init__(self, management_public_ip, asav_password, ssh_port=22, asav_username='admin'):
        self.ip_to_connect = management_public_ip
        self.port = ssh_port
        self.username = asav_username
        self.password = asav_password
        self.defaultPassword = 'AsAv_AuT0Scale'
        self.COMMAND_RAN = 'COMMAND_RAN'
        self.SUCCESS = 'SUCCESS'
        self.FAIL = 'FAILURE'

    def connect_asa(self):
        """
        Purpose:    This provides object of ParamikoSSH class
        Parameters:
        Returns:    Class object, None
        Raises:
        """

        connect = ParamikoSSH(self.ip_to_connect, self.port, self.username, self.password)
        logger.debug(connect)
        return connect

    # Run an independent command on FTDv
    def run_asav_command(self, command):
        """
        Purpose:    To run a single command
        Parameters: command
        Returns:    'FAILURE', 'COMMAND_RAN'
        Raises:
        """
        output, error = '', ''
        cnt_asa = self.connect_asa()
        try:
            status, output, error = cnt_asa.execute_cmd(command)
        except Exception as e:
            logger.error("POST LAUNCH ACTION: Error occurred: {}".format(repr(e)))
            cnt_asa.close()
            return self.FAIL, output, error
        if status == self.SUCCESS:
            logger.debug("%s %s %s" % (self.COMMAND_RAN, output, error))
            cnt_asa.close()
            return self.COMMAND_RAN, output, error
        else:
            logger.warn("POST LAUNCH ACTION: Unable to run command output: %s error: %s" % (output, error))
            cnt_asa.close()
            return self.FAIL, output, error

    # function to change password(admin) from prev_password to new_password
    def change_asa_password(self, cnt_asa, prev_password, new_password):
        """
        Purpose:    To change password from default to user provided
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        write_memory_config = 'copy /noconfirm running-config startup-config'
        expected_outcome_write_memory_config = '#'
        change_password_cmd = "change-password old-password " + prev_password + " new-password " + new_password
        change_enable_password_cmd = 'enable ' + 'password ' + new_password
        command_set = {
            "cmd": [
                {
                    "command": "login",
                    "expect": "Username:"
                },
                {
                    "command": self.username,
                    "expect": "Password:"
                },
                {
                    "command": prev_password,
                    "expect": "#"
                },
                {
                    "command": change_password_cmd,
                    "expect": "#"
                },
                {
                    "command": "configure terminal",
                    "expect": "(config)#"
                },
                {
                    "command": "A",
                    "expect": "#"
                },
                {
                    "command": change_enable_password_cmd,
                    "expect": "#"
                },
                {
                    "command": write_memory_config,
                    "expect": expected_outcome_write_memory_config
                }
            ]
        }

        try:
            cnt_asa.handle_interactive_session(command_set, self.username, prev_password)
        except ValueError as e:
            logger.error("POST LAUNCH ACTION: Error occurred: {}".format(repr(e)))
            return None
        else:
            return 'SUCCESS'
        finally:
            cnt_asa.close()

    def check_asav_ssh_status(self):
        """
        Purpose:    To check ASAv SSH is accessible
        Parameters:
        Returns:    SUCCESS, FAILURE
        Raises:
        """
        cnt_asa = self.connect_asa()
        status = cnt_asa.connect(self.username, self.password)
        logger.info("POST LAUNCH ACTION: ASAv SSH Connect Status : {}".format(status))
        if status == 'SUCCESS':
            cnt_asa.close()
            return 'SUCCESS'
        elif status == 'Authentication Exception Occurred':
            status = cnt_asa.connect(self.username, self.defaultPassword)
            if status == 'SUCCESS':
                cnt_asa.close()  # As below function triggers interactive shell
                if self.change_asa_password(cnt_asa, self.defaultPassword, self.password) == 'SUCCESS':
                    return 'SUCCESS'
            else:
                logger.error("POST LAUNCH ACTION: Unable to authenticate to ASAv instance, please check password!")
                return 'FAILURE'
        else:
            cnt_asa.close()
        return 'FAILURE'

    # Polling connectivity to FTDv for specified 'minutes'
    def poll_asav_ssh(self, minutes):
        """
        Purpose:    To poll ASAv for SSH accessibility
        Parameters: Minutes
        Returns:    SUCCESS, TIMEOUT
        Raises:
        """
        logger.info("POST LAUNCH ACTION: Checking if instance SSH access is available!")
        if minutes <= 1:
            minutes = 2
        for i in range(1, 2 * minutes):
            if i != ((2 * minutes) - 1):
                status = self.check_asav_ssh_status()
                if status != "SUCCESS":
                    logger.info(str(i) + " Sleeping for 30 seconds")
                    time.sleep(30)
                else:
                    return "SUCCESS"
        logger.info("POST LAUNCH ACTION: Failed to connect to device retrying... ")
        return "TIMEOUT"

    def configure_hostname(self, vm_name):
        """
        Purpose:    To configure hostname on ASAv
        Parameters:
        Returns:    'FAILURE', 'COMMAND_RAN'
        Raises:
        """
        cnt_asa = self.connect_asa()
        cmd = 'hostname ' + vm_name
        expected_outcome = vm_name + "(config)#"
        write_memory_config = 'copy /noconfirm running-config startup-config'
        expected_outcome_write_memory_config = '#'
        command_set = {
            "cmd": [
                {
                    "command": "enable",
                    "expect": "Password:"
                },
                {
                    "command": self.password,
                    "expect": "#"
                },
                {
                    "command": "conf t",
                    "expect": "(config)#"
                },
                {
                    "command": cmd,
                    "expect": expected_outcome
                },
                {
                    "command": write_memory_config,
                    "expect": expected_outcome_write_memory_config
                }
            ]
        }
        try:
            cnt_asa.handle_interactive_session(command_set, self.username, self.password)
        except ValueError as e:
            logger.error(f"POST LAUNCH ACTION: Error occurred in host name configuration: {repr(e)}")
            return self.FAIL
        else:
            return self.SUCCESS

    def run_copy_file_running_config(self, url, file_path):
        """
        Purpose:    To change configure running-config from HTTP/HTTPS
        Parameters: url, s3 bucket/any http server path
        Returns:    SUCCESS, None
        Raises:
        """
        cmd1 = 'copy /noconfirm ' + url + ' ' + file_path
        cmd2 = 'copy /noconfirm ' + file_path + ' running-config'
        write_memory_config = 'copy /noconfirm running-config startup-config'
        expected_outcome_write_memory_config = '#'
        command_set = {
            "cmd": [
                {
                    "command": "enable",
                    "expect": "Password:"
                },
                {
                    "command": self.password,
                    "expect": "#"
                },
                {
                    "command": "conf t",
                    "expect": "#"
                },
                {
                    "command": cmd1,
                    "expect": "#"
                },
                {
                    "command": cmd2,
                    "expect": "#"
                },
                {
                    "command": write_memory_config,
                    "expect": expected_outcome_write_memory_config
                }
            ]
        }
        # Do not print below log, will print password on log
        # logger.info("Initiating configuration of ASAv with command set: "
        #             + json.dumps(command_set, separators=(',', ':')))
        logger.debug("Executing commands: " + cmd1)
        logger.debug("Executing commands: " + cmd2)
        cnt_asa = self.connect_asa()
        try:
            cnt_asa.handle_interactive_session(command_set, self.username, self.password)
        except ValueError as e:
            logger.error("POST LAUNCH ACTION: Error occurred: {}".format(repr(e)))
            return None
        else:
            return 'SUCCESS'
        finally:
            cnt_asa.close()


    def one_time_interface_configuration(self, inside_interface_ip, inside_subnet_netmask, outside_interface_ip, outside_subnet_netmask):
        """
        Purpose:
        Parameters:
        Returns:    SUCCESS, None
        Raises:
        """
        cmd1 = "ip address "+str(inside_interface_ip)+" "+str(inside_subnet_netmask)
        cmd2 = "ip address "+str(outside_interface_ip)+" "+str(outside_subnet_netmask)
        write_memory_config = 'copy /noconfirm running-config startup-config'
        expected_outcome_write_memory_config = '#'
        command_set = {
            "cmd": [
                {
                    "command": "enable",
                    "expect": "Password:"
                },
                {
                    "command": self.password,
                    "expect": "#"
                },
                {
                    "command": "conf t",
                    "expect": "#"
                },
                {
                    "command": "int g0/0",
                    "expect": "#"
                },
                {
                    "command": "nameif inside",
                    "expect": "#"
                },
                {
                    "command": cmd1,
                    "expect": "#"
                },
                {
                    "command": "no shut",
                    "expect": "#"
                },
                {
                    "command": "int g0/1",
                    "expect": "#"
                },
                {
                    "command": "nameif outside",
                    "expect": "#"
                },
                {
                    "command": cmd2,
                    "expect": "#"
                },
                {
                    "command": "no shut",
                    "expect": "#"
                },
                {
                    "command": write_memory_config,
                    "expect": expected_outcome_write_memory_config
                }
            ]
        }
        # Do not print below log, will print password on log
        # logger.info("Initiating configuration of ASAv with command set: "
        #             + json.dumps(command_set, separators=(',', ':')))
        cnt_asa = self.connect_asa()
        try:
            cnt_asa.handle_interactive_session(command_set, self.username, self.password)
        except ValueError as e:
            logger.error("POST LAUNCH ACTION: Error occurred: {}".format(repr(e)))
            return None
        else:
            return 'SUCCESS'
        finally:
            cnt_asa.close()

class PostLaunchAction:
    def __init__(self, auth):
        self.signer = auth
        self.computeClient = oci.core.ComputeClient(config={}, signer=auth)
        self.virtualNetworkClient = oci.core.VirtualNetworkClient(config={}, signer=auth)
        self.computeManagementClient = oci.core.ComputeManagementClient(config={}, signer=auth)
        self.loadBalancerClient = oci.load_balancer.LoadBalancerClient(config={}, signer=auth)
        self.retries = 3

    def get_all_instances_id_in_pool(self, compartmentId, instancePoolId):
        """
        Purpose:   To get OCID of all Instances in the Instance Pool
        Parameters: Compartment OCID, Instance Pool OCID
        Returns:    List(Instance OCID)
        Raises:
        """
        for i in range(0, self.retries):
            try:
                all_instances_in_instance_pool = self.computeManagementClient.list_instance_pool_instances(
                                            compartment_id = compartmentId,
                                            instance_pool_id = instancePoolId).data

                all_instances_id = [instance.id for instance in all_instances_in_instance_pool]
                return all_instances_id

            except Exception as e:
                logger.error("POST LAUNCH ACTION: ERROR IN GETTING INSTANCE LIST FROM INSTANCE POOL, RETRY COUNT:{0}, REASON:{1}".format(str(i+1), repr(e)))
                continue

        return None

    def terminate_instance(self, instanceId):
        """
        Purpose:   To Terminate any Instance in the Instance Pool (Not Scale-In)
        Parameters: Instance OCID to delete.
        Returns:    Boolean
        Raises:
        """
        for i in range(0, self.retries):
            try:
                terminate_instance_response = self.computeClient.terminate_instance(
                instance_id = instanceId,
                preserve_boot_volume=False)

                logger.info("POST LAUNCH ACTION: INSTANCE TERMINATED AS SOMETHING WENT WRONG, PLEASE CHECK PREVIOUS LOGS")
                return True

            except Exception as e:
                logger.info("POST LAUNCH ACTION: ERROR OCCURRED WHILE TERMINATING INSTANCE, RETRY COUNT:{0}, REASON:{1}".format(str(i+1), repr(e)))
                continue
        return False

    def get_management_public_ip(self, compartmentId, instanceId):
        """
        Purpose:    To get Management interface (vnic) public IP.
        Parameters: Compartment OCID, Instance OCID.
        Returns:    Dict     Example: {'management_public_ip': '54.88.96.211'}
        Raises:
        """
        for i in range(0, self.retries):
            try:
                vnic_attachments = oci.pagination.list_call_get_all_results(
                self.computeClient.list_vnic_attachments,
                compartment_id = compartmentId,
                instance_id = instanceId,
                ).data

                vnics = [self.virtualNetworkClient.get_vnic(va.vnic_id).data for va in vnic_attachments]

                for vnic in vnics:
                    if vnic.is_primary:
                        ip_response = vnic.public_ip
                        return ip_response

            except Exception as e:
                logger.error("POST LAUNCH ACTION: ERROR IN RETRIEVING MANAGEMENT PUBLIC IP "+"RETRY COUNT:"+str(i)+"  "+ repr(e))
                continue

        return None

    def attach_interface(self, instanceId, interfaceName, subnetId, nsgIdList):
        """
        Purpose:   To create Non-primary interface (vnic) in a Instance.
        Parameters: Instance OCID, Interface Name, Subnet OCID
        Returns:    A Response object with data of type VnicAttachment
        Raises:
        """
        for i in range(1, self.retries+1):
            try:
                computeCompositeClient = oci.core.ComputeClientCompositeOperations(client=self.computeClient)

                attach_vnic_details=oci.core.models.AttachVnicDetails(
                create_vnic_details=oci.core.models.CreateVnicDetails(
                    assign_public_ip = False,
                    skip_source_dest_check = True,
                    subnet_id = subnetId,
                    nsg_ids = nsgIdList),
                    instance_id = instanceId,
                    display_name = interfaceName)

                attach_vnic_response = computeCompositeClient.attach_vnic_and_wait_for_state(attach_vnic_details, wait_for_states=["ATTACHED", "UNKNOWN_ENUM_VALUE"]).data
                vnicId = attach_vnic_response.vnic_id

            except Exception as e:
                logger.error("POST LAUNCH ACTION: RETRY: {} ERROR IN ATTACHING {} VNIC, ERROR {}".format(i, interfaceName, e))
                time.sleep(10)
                continue
            """
            NOTE: Code following below for this function has been written to update VNIC name after attachment
            because it is not taking given display name at them time of attachment itself.
            If the issue gets resolved in future this code should be removed.
            """
            try:
                virtualNetworkCompositeClient = oci.core.VirtualNetworkClientCompositeOperations(client = self.virtualNetworkClient)
                update_vnic_details=oci.core.models.UpdateVnicDetails(display_name = interfaceName)
                update_vnic_response = virtualNetworkCompositeClient.update_vnic_and_wait_for_state(vnicId, update_vnic_details, wait_for_states=["AVAILABLE", "UNKNOWN_ENUM_VALUE"]).data
                return update_vnic_response

            except Exception as e:
                logger.error("POST LAUNCH ACTION:  RETRY: {} ERROR IN UPDATING {} VNIC, ERROR {}".format(i, interfaceName, e))
        return None

    def add_to_backend_set(self, loadBalancerId, backendSetName, ipAddr, portNo):
        """
        Purpose:   To add instacne as backend server to the backend set of the load balancer
        Parameters: Ip Address of instance, Port Number, Backend set name, Load Balancer OCID
        Returns:    Str
        Raises:
        """
        for i in range(0, self.retries):
            try:
                create_backend_response = self.loadBalancerClient.create_backend(
                    create_backend_details = oci.load_balancer.models.CreateBackendDetails(
                                                ip_address = ipAddr,
                                                port = portNo,
                                                #weight=,
                                                #backup=True,
                                                #drain=False,
                                                #offline=False
                                            ),
                        load_balancer_id = loadBalancerId,
                        backend_set_name = backendSetName
                        ).data
                return "Successful"

            except Exception as e:
                logger.error("POST LAUNCH ACTION: ERROR IN ADDING TO BACKEND SET "+"RETRY COUNT:"+str(i+1)+"  "+ repr(e) + repr(create_backend_response))
                continue

        return "Failed"

    def get_netmask_from_subnet_cidr(self, subnetId):
        """
        Purpose:   To calculate Netmask of Subnet.
        Parameters: Subnet OCID
        Returns:    Str
        Raises:
        """
        try:
            subnet_cidr = (self.virtualNetworkClient.get_subnet(subnet_id = subnetId).data).cidr_block
            (addrString, cidrString) = subnet_cidr.split('/')
            cidr = int(cidrString)

            mask = [0, 0, 0, 0]
            for i in range(cidr):
                mask[int(i/8)] = mask[int(i/8)] + (1 << (7 - i % 8))

            netmask = ".".join(map(str, mask))
            return netmask
        except Exception as e:
            logger.error("POST LAUNCH ACTION: ERROR IN CALCULATING NETMASK"+repr(e))
            return None

    def decrypt_cipher(self, cipherText, cryptEndpoint, keyId):
        """
        Purpose:   To decrypt encrypted password.
        Parameters: Encrypted Password, Cryptographic Endpoint, Master Key OCID
        Returns:    password in plaintext (str)
        Raises:
        """
        for i in range(0, self.retries):
            try:
                key_management_client = oci.key_management.KmsCryptoClient(config={}, signer = self.signer, service_endpoint = cryptEndpoint)

                decrypt_response = key_management_client.decrypt(
                    decrypt_data_details=oci.key_management.models.DecryptDataDetails(
                        ciphertext = cipherText,
                        key_id = keyId)).data

                return base64.b64decode(decrypt_response.plaintext).decode('utf-8')

            except Exception as e:
                logger.error("POST LAUNCH ACTION: ERROR IN DECRYPTING PASSWORD ERROR: {}".format(e))
                continue

        return None


def handler(ctx, data: io.BytesIO=None):
    """
        Purpose:   Main Function, receive JSON payload, Environmental Variable, implementation logic.
        Parameters: ctx (Contains Environmental Variables passed), data (Json Payload emit by event which called this function)
        Returns:    Response
        Raises:
        """
    try:
        body = json.loads(data.getvalue())
        data = body.get("data")
        instanceId = data.get("resourceId")
        compartmentId = data.get("compartmentId")

        logger.info("POST LAUNCH ACTION HAS BEEN CALLED FOR INSTANCE ID: {0}".format(instanceId))
    except Exception as ex:
        logger.error('POST LAUNCH ACTION: ERROR IN PARSING JSON PAYLOAD, PLEASE MANUALLY DELETE THE INSTANCE FOR WHICH IT FAILED: ' + repr(ex))
        return "POST LAUNCH ACTION: ERROR IN PARSING JSON PAYLOAD"

    try:
        signer = oci.auth.signers.get_resource_principals_signer()
    except Exception as e:
        logger.error("POST LAUNCH ACTION: ERROR IN OBTAINING SIGNER  "+repr(e))
        logger.info("AFTER FIXING ISSUE WITH SIGNER, PLEASE MANUALLY DELETE THE INSTANCE FOR WHICH IT FAILED")
        return "POST LAUNCH ACTION: FAILED TO CREATE SIGNER"

    # POST LAUNCH ACTION CLASS OBJECT
    postLaunchActionObject = PostLaunchAction(signer)

    try:
        environmentVariables = ctx.Config()
        outsideInterfaceName = environmentVariables["outside_interface_name"]
        outsideSubnetId = environmentVariables["outside_subnet_id"]
        ELB_Id = environmentVariables["elb_id"]
        ELB_BackendSetName = environmentVariables["elb_backend_set_name"]
        ELB_ListenerPortNumber = (environmentVariables["elb_listener_port_no"])
        instancePoolId = environmentVariables["instance_pool_id"]
        insideInterfaceName = environmentVariables["inside_interface_name"]
        insideSubnetId = environmentVariables["inside_subnet_id"]
        ILB_Id = environmentVariables["ilb_id"]
        ILB_BackendSetName = environmentVariables["ilb_backend_set_name"]
        ILB_ListenerPortNumber = (environmentVariables["ilb_listener_port_no"])
        configuration_file_url = environmentVariables["configuration_file_url"]
        outsideNSGId = environmentVariables["outside_nsg_id"]
        insideNSGId = environmentVariables["inside_nsg_id"]
        asavEncryptedPassword = environmentVariables["encrypted_password"]
        cryptEndpoint = environmentVariables["cryptographic_endpoint"]
        master_key_id = environmentVariables["master_key_id"]

    except Exception as e:
        logger.error("POST LAUNCH ACTION: ERROR IN RETRIEVING ENVIRONMENT VARIABLES "+repr(e))
        return "POST LAUNCH ACTION FAILED WITH THIS INSTANCE"

    all_instances_id = postLaunchActionObject.get_all_instances_id_in_pool(compartmentId, instancePoolId)
    if all_instances_id == None:
        return

    if instanceId in all_instances_id:
        try:
            time.sleep(20) # To give enough time for management vnic to come up properly.
            ############################### ATTACHING INSIDE VNIC ################################
            attach_inside_interface_response = postLaunchActionObject.attach_interface(instanceId, insideInterfaceName, insideSubnetId, [insideNSGId])
            if attach_inside_interface_response != None:
                logger.info("POST LAUNCH ACTION Response : INSIDE VNIC attached successfully")
                insideInterfaceIpAddress = attach_inside_interface_response.private_ip
            else:
                logger.error("POST LAUNCH ACTION: Inside VNIC Attachment Failed, INSTACE WILL BE TERMINATED")
                terimate_instance_response = postLaunchActionObject.terminate_instance(instanceId)
                return "POST LAUNCH ACTION FAILED WITH THIS INSTANCE"
            #=======================================================================================#
            ############################### ATTACHING OUTSIDE VNIC ##################################
            attach_outside_interface_response = postLaunchActionObject.attach_interface(instanceId, outsideInterfaceName, outsideSubnetId, [outsideNSGId])
            if attach_outside_interface_response != None:
                logger.info("POST LAUNCH ACTION Response : Outside VNIC attached successfully")
                outsideInterfaceIpAddress = attach_outside_interface_response.private_ip
            else:
                logger.error("POST LAUNCH ACTION: Outside VNIC Attachment Failed INSTACE WILL BE TERMINATED")
                terimate_instance_response = postLaunchActionObject.terminate_instance(instanceId)
                return "POST LAUNCH ACTION FAILED WITH THIS INSTANCE"
            #====================================================================================#
        except Exception as e:
            logger.error("POST LAUNCH ACTION: EXCEPTION OCCURED WHILE ATTACHING THE INTERFACES, INSTACE WILL BE TERMINATED   "+repr(e))
            terimate_instance_response = postLaunchActionObject.terminate_instance(instanceId)
            return "POST LAUNCH ACTION FAILED WITH THIS INSTANCE"

        ############################### ADDING TO INTERNAL LOAD BALANCER ##########################
        # Note: ILB_ListenerPortNumber is passed in the form of string so we need to create list out of it.
        ilb_listener_port_list = list(map(lambda x: int(x.strip()), ILB_ListenerPortNumber.split(',')))
        try:
            for iPort in ilb_listener_port_list:
                add_to_ILB_backend_set_response = postLaunchActionObject.add_to_backend_set(ILB_Id, ILB_BackendSetName, insideInterfaceIpAddress, iPort)
                logger.info("POST LAUNCH ACTION: Add to Internal Backend Set response for listener port {0} is {1}".format(iPort, repr(add_to_ILB_backend_set_response)))
        except Exception as e:
            logger.error("POST LAUNCH ACTION: ADD TO INTERNAL BACKEND SET ACTION GOT FAILED INSTACE WILL BE TERMINATED  "+repr(e))
            terimate_instance_response = postLaunchActionObject.terminate_instance(instanceId)
            return "POST LAUNCH ACTION FAILED WITH THIS INSTANCE"
        #===========================================================================================#
        ############################# ADDING TO EXTERNAL LOAD BALANCER ##############################
        # Note: ELB_ListenerPortNumber is passed in the form of string so we need to create list out of it.
        elb_listener_port_list = list(map(lambda x: int(x.strip()), ELB_ListenerPortNumber.split(',')))
        try:
            for ePort in elb_listener_port_list:
                add_to_ELB_backend_set_response = postLaunchActionObject.add_to_backend_set(ELB_Id, ELB_BackendSetName, outsideInterfaceIpAddress, ePort)
                logger.info("POST LAUNCH ACTION: Add to external backend set response for listener port {0} is {1} ".format(ePort, repr(add_to_ELB_backend_set_response)))
        except Exception as e:
            logger.error("POST LAUNCH ACTION: ADD TO EXTERNAL BACKEND SET ACTION GOT FAILED INSTACE WILL BE TERMINATED  "+repr(e))
            terimate_instance_response = postLaunchActionObject.terminate_instance(instanceId)
            return "POST LAUNCH ACTION FAILED WITH THIS INSTANCE"
        #===========================================================================================#
        ############################### CONFIGURING ASAV VIA SSH ####################################

        #RETRIEVING NETMASK FROM SUBNET CIDR
        insideSubnetNetmask = postLaunchActionObject.get_netmask_from_subnet_cidr(insideSubnetId)
        outsideSubnetNetmask = postLaunchActionObject.get_netmask_from_subnet_cidr(outsideSubnetId)

        logger.info("POST LAUNCH ACTION: Waiting for ASAv to complete first time boot ...")
        time.sleep(80)

        try:
            management_public_ip = postLaunchActionObject.get_management_public_ip(compartmentId, instanceId)
            if management_public_ip == None:
                logger.info("POST LAUNCH ACTION: INSTACE WILL BE TERMINATED")
                terimate_instance_response = postLaunchActionObject.terminate_instance(instanceId)
                return "POST LAUNCH ACTION FAILED WITH THIS INSTANCE"

            asavPassword = postLaunchActionObject.decrypt_cipher(asavEncryptedPassword, cryptEndpoint, master_key_id)
            asav = ASAvInstance(management_public_ip, asavPassword)
            asav_ssh_status = asav.poll_asav_ssh(4)
            if asav_ssh_status != 'SUCCESS':
                logger.error("POST LAUNCH ACTION: NOT ABLE TO GET SSH ON ASAV, INSTACE WILL BE TERMINATED")
                terimate_instance_response = postLaunchActionObject.terminate_instance(instanceId)
                return "POST LAUNCH ACTION FAILED WITH THIS INSTANCE"

            one_time_interface_configuration_response = asav.one_time_interface_configuration(insideInterfaceIpAddress, insideSubnetNetmask, outsideInterfaceIpAddress,outsideSubnetNetmask)
            if one_time_interface_configuration_response != "SUCCESS":
                logger.info("POST LAUNCH ACTION: ERROR OCCURRED IN INTERFACE CONFIGURATION, INSTACE WILL BE TERMINATED")
                terimate_instance_response = postLaunchActionObject.terminate_instance(instanceId)
                return "POST LAUNCH ACTION FAILED WITH THIS INSTANCE"
            else:
                logger.info("POST LAUNCH ACTION: Interfaces have been configured successfully")

            # CONFIGURING HOSTNAME
            vm_name = "ciscoasa-" + instanceId[-5:]
            hostname_response = asav.configure_hostname(vm_name)
            logger.info(f"POST LAUNCH ACTION: ASAv instance Hostname configuration response {hostname_response}")

            asav_configuration_file_local_path = 'disk0:configuration.txt'
            asav_response = asav.run_copy_file_running_config(configuration_file_url, asav_configuration_file_local_path)
            if asav_response != 'SUCCESS':
                logger.error("POST LAUNCH ACTION: CONFIGURE ASAV ACTION GOT FAILED")
                return None
            else:
                logger.info("POST LAUNCH ACTION: Configure ASAv action performed successfully for instance {}".format(instanceId))

        except Exception as e:
            logger.critical("POST LAUNCH ACTION: ERROR IN CONFIGURE ASAV ACTION, INSTACE WILL BE TERMINATED "+repr(e))
            terimate_instance_response = postLaunchActionObject.terminate_instance(instanceId)
            return "POST LAUNCH ACTION FAILED WITH THIS INSTANCE"

        return response.Response(
            ctx, response_data=json.dumps(
                {"Response": "Post Launch Action Performed Successfully"}),
        headers={"Content-Type": "application/json"}
        )

    else:
        logger.info("POST LAUNCH ACTION: Instance does not belongs to particular Instance Pool, Hence no action performed")
        return "Instance does not belongs to particular Instance Pool"
