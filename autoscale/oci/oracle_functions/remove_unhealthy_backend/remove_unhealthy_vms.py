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

Name:       remove_unhealthy_vms.py
Purpose:    This python file has ASAv related class & methods
            Classes in this python files are being used for 
            performing Remove-Unhealthy-Backend action in OCI ASAv Autoscale.
"""

import io
import json
import logging

import paramiko
import socket
import time
import oci
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
        self.retry = 7

    def close(self):
        self.ssh.close()

    def verify_server_ip(self):
        try:
            socket.inet_aton(self.server)
            return self.SUCCESS
        except socket.error as e:
            logger.error("REMOVE UNHEALTHY BACKEND FUNCTION: Exception occurred: {}".format(repr(e)))
            return self.FAIL
        except Exception as e:
            logger.error("REMOVE UNHEALTHY BACKEND FUNCTION: Exception occurred: {}".format(repr(e)))
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
        flag = self.FAIL
        for i in range(1, self.retry):
            try:
                self.ssh.connect(self.server, self.port, username, password, timeout=60, banner_timeout=90//i, auth_timeout=60)
                logger.debug(f"CONFIGURE ASAv {self.identifier}: (connect) Connection to {self.server} on port {self.port} is successful!")
                return self.SUCCESS
            except paramiko.AuthenticationException as exc:
                logger.warn(f"CONFIGURE ASAv {self.identifier}: (connect) Exception occurred: {repr(exc)}")
                flag = self.AUTH_EXCEPTION
                time.sleep(10)
            except paramiko.BadHostKeyException as exc:
                logger.debug(f"CONFIGURE ASAv {self.identifier}:(connect) Exception occurred: {repr(exc)}")
                flag = self.BAD_HOST_KEY_EXCEPTION
                time.sleep(10)
            except paramiko.SSHException as exc:
                logger.debug(f"CONFIGURE ASAv {self.identifier}: (connect) Exception occurred: {repr(exc)}")
                flag = self.SSH_EXCEPTION
                time.sleep(10)
            except BaseException as exc:
                logger.debug(f"CONFIGURE ASAv {self.identifier}: (connect) Exception occurred: {repr(exc)}")
                flag = self.FAIL
                time.sleep(10)
        logger.warning(f"CONFIGURE ASAv {self.identifier}: (connect) Connect to server response {flag}")
        return flag

    def execute_cmd(self, command):
        """
        Purpose:    Performs an interactive shell action
        Parameters: Command
        Returns:    action status, output & error
        """
        if self.connect(self.username, self.password) != self.SUCCESS:
            raise ValueError("REMOVE UNHEALTHY BACKEND FUNCTION: Unable to connect to server")
        try:
            ssh_stdin, ssh_stdout, ssh_stderr = self.ssh.exec_command(command, timeout=self.timeout)
        except paramiko.SSHException as exc:
            logger.error("REMOVE UNHEALTHY BACKEND FUNCTION: Exception occurred: {}".format(repr(exc)))
            self.ssh.close()
            return self.FAIL, None, None
        else:
            output = ssh_stdout.readlines()
            error = ssh_stderr.readlines()
            logger.debug('REMOVE UNHEALTHY BACKEND FUNCTION: SSH command output: ' + str(output))
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
            logger.error("REMOVE UNHEALTHY BACKEND FUNCTION: Exception occurred: {}".format(repr(exc)))
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
            raise ValueError("REMOVE UNHEALTHY BACKEND FUNCTION: Unable to connect to server")
        status, shell = self.invoke_interactive_shell()
        if status != self.SUCCESS:
            raise ValueError("REMOVE UNHEALTHY BACKEND FUNCTION: Unable to invoke shell")
        if self.send_cmd_and_wait_for_execution(shell, '\n') is not None:
            for key in command_set:
                set = command_set[key]
                for i in range(0, len(set)):
                    command = set[i]['command'] + '\n'
                    expect = set[i]['expect']
                    if self.send_cmd_and_wait_for_execution(shell, command, expect) is not None:
                        pass
                    else:
                        raise ValueError("REMOVE UNHEALTHY BACKEND FUNCTION: Unable to execute command!")
        return

    def send_cmd_and_wait_for_execution(self, shell, command, wait_string='>'):
        """
        Purpose:    Sends command and waits for string to be received
        Parameters: command, wait_string
        Returns:    rcv_buffer or None
        Raises:
        """
        shell.settimeout(self.timeout)
        total_msg = ""
        rcv_buffer = b""
        print(f"Running Command : {command}, Wait String {wait_string}")
        try:
            shell.send(command)
            while wait_string not in rcv_buffer.decode("utf-8"):
                if shell.recv_ready():
                    rcv_buffer = shell.recv(10000)
                    total_msg = total_msg + ' ' + rcv_buffer.decode("utf-8")
            logger.debug(f"REMOVE UNHEALTHY BACKEND FUNCTION: Command Output: {total_msg}")
            return total_msg
        except Exception as e:
            logger.error(f"REMOVE UNHEALTHY BACKEND FUNCTION: (send_cmd_and_wait_for_execution) Command:{repr(command)}, Wait string:{wait_string}, Buffer: {total_msg} ERROR:{repr(e)}")
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
        self.defaultPassword = 'Admin123'
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

    def check_asav_ssh_status(self):
        """
        Purpose:    To check ASAv SSH is accessible
        Parameters:
        Returns:    SUCCESS, FAILURE
        Raises:
        """
        cnt_asa = self.connect_asa()
        status = cnt_asa.connect(self.username, self.password)
        if status == 'SUCCESS':
            return 'SUCCESS'
        else:
            logger.error("REMOVE UNHEALTHY BACKEND FUNCTION: Unable to authenticate to ASAv instance")
            return 'FAILURE'
        return 'FAILURE'
    
    def poll_asav_ssh(self, minutes):
        """
        Purpose:    To poll ASAv for SSH accessibility
        Parameters: Minutes
        Returns:    SUCCESS, TIMEOUT
        Raises:
        """
        logger.info("Checking if instance SSH access is available!")
        if minutes <= 1:
            minutes = 2
        for i in range(1, 6 * minutes):
            if i != ((2 * minutes) - 1):
                status = self.check_asav_ssh_status()
                if status != "SUCCESS":
                    logger.debug(str(i) + " Retrying in 10 sec")
                    time.sleep(1 * 10)
                else:
                    return "SUCCESS"
        logger.info("REMOVE UNHEALTHY BACKEND FUNCTION: Failed to connect to device retrying... ")
        return "TIMEOUT"

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
            logger.error("REMOVE UNHEALTHY BACKEND FUNCTION: Error occurred: {}".format(repr(e)))
            return self.FAIL, output, error
        if status == self.SUCCESS:
            logger.debug("REMOVE UNHEALTHY BACKEND FUNCTION: %s %s %s" % (self.COMMAND_RAN, output, error))
            return self.COMMAND_RAN, output, error
        else:
            logger.warn("REMOVE UNHEALTHY BACKEND FUNCTION: Unable to run command output: %s error: %s" % (output, error))
            return self.FAIL, output, error

    def verify_string_match(self, command, verify_string):
        """
        Purpose:    To verify string match
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        cnt_asa = self.connect_asa()
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
                    "command": command,
                    "expect": verify_string
                }
            ]
        }
        logger.info("Running Command: " + command)
        logger.info("Expecting String: " + verify_string)
        try:
            cnt_asa.handle_interactive_session(command_set, self.username, self.password)
        except ValueError as e:
            logger.debug("REMOVE UNHEALTHY BACKEND FUNCTION: Error occurred: {}".format(repr(e)))
            # logger.debug("It's likely that verify_string didn't match for command")
            return self.FAIL
        except Exception as e:
            logger.error("REMOVE UNHEALTHY BACKEND FUNCTION: Error occurred: {}".format(repr(e)))
            return self.FAIL
        else:
            logger.info("REMOVE UNHEALTHY BACKEND FUNCTION: Found String: " + verify_string)
            return self.SUCCESS
        finally:
            cnt_asa.close()

    def deregister_smart_license(self):
        """
        Purpose:    To deregister smart license
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        cmd1 = 'show license status'
        cmd2 = 'license smart deregister'
        cnt_asa = self.connect_asa()
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
                    "command": cmd2,
                    "expect": "#"
                },
                {
                    "command": write_memory_config,
                    "expect": expected_outcome_write_memory_config
                }
            ]
        }
        # logger.info("Initiating de-registration of ASAv with command set: "
        #             + json.dumps(command_set, separators=(',', ':')))
        try:
            cnt_asa.handle_interactive_session(command_set, self.username, self.password)
        except ValueError as e:
            logger.error("REMOVE UNHEALTHY BACKEND FUNCTION: Error occurred: {}".format(repr(e)))
            return self.FAIL
        else:
            return self.SUCCESS
        finally:
            cnt_asa.close()

    def verify_asa_license_unregistered(self):
        """
        Purpose:    To verify smart license UNREGISTERED
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        command = 'show license summary'
        verify_string = 'UNREGISTERED'
        return self.verify_string_match(command, verify_string)

class RemoveBackend:
    def __init__(self, auth):
        self.signer = auth
        self.computeClient = oci.core.ComputeClient(config={}, signer=auth)
        self.virtualNetworkClient = oci.core.VirtualNetworkClient(config={}, signer=auth)
        self.computeManagementClient = oci.core.ComputeManagementClient(config={}, signer=auth)
        self.loadBalancerClient = oci.load_balancer.LoadBalancerClient(config={}, signer=auth)
        self.retries = 3

    def terminate_instance(self, instanceId):
        """
        Purpose:   To Terminate instance
        Parameters: 
        Returns:    Response
        Raises:
        """
        try:
            terminate_instance_response = self.computeClient.terminate_instance(
            instance_id = instanceId,
            preserve_boot_volume=False)

            logger.info("REMOVE UNHEALTHY BACKEND FUNCTION: INSTANCE TERMINATED AS SOMETHING WENT WRONG, PLEASE CHECK PREVIOUS LOGS")
            return terminate_instance_response
        
        except Exception as e:
            logger.info("REMOVE UNHEALTHY BACKEND FUNCTION: ERROR OCCURRED WHILE TERMINATING INSTANCE" + repr(e))
            return None

    def get_unhealthy_backends(self, loadBalancerId, backendSetName):
        """
        Purpose:   To get list of all the unhealthy backends in the Instance Pool.
        Parameters: Load Balancer OCID, Backend Set Name
        Returns:    list(Obj(Instnace))
        Raises:
        """
        try:
            backend_set_health_response = self.loadBalancerClient.get_backend_set_health(
            load_balancer_id = loadBalancerId,
            backend_set_name = backendSetName).data

            logger.error("REMOVE UNHEALTHY BACKEND FUNCTION: Backend Set Health retrieved successfully")
            return backend_set_health_response
        except Exception as e:
            logger.error("REMOVE UNHEALTHY BACKEND FUNCTION  "+repr(e))
            return None

    def get_all_instances_in_pool(self, compartmentId, instancePoolId):
        """
        Purpose:   To get ID of all instances in the Instance Pool 
        Parameters: 
        Returns:    Response
        Raises:
        """
        for i in range(0, self.retries):
            try:
                all_instances_in_instance_pool = self.computeManagementClient.list_instance_pool_instances(
                                            compartment_id = compartmentId,
                                            instance_pool_id = instancePoolId).data

            
                return all_instances_in_instance_pool

            except Exception as e:
                logger.error("REMOVE UNHEALTHY BACKEND FUNCTION: ERROR IN GETTING INSTANCE LIST FROM INSTANCE POOL, RETRY COUNT:{0}, REASON:{1}".format(str(i+1), repr(e)))
                continue
        
        return None

    def get_instance_interface_ip(self, compartmentId, instanceId, insideInterfaceName, outsideInterfaceName):
        """
        Purpose:    
        Parameters:
        Returns:    Dict
                Example: {'inside_ip': '10.0.100.139','outside_ip': '10.0.200.116'}   
        Raises:
        """
        interface_ip = {}
        try:
            vnic_attachments = oci.pagination.list_call_get_all_results(
            self.computeClient.list_vnic_attachments,
            compartment_id = compartmentId,
            instance_id = instanceId
            ).data
        except Exception as e:
            logger.error("REMOVE UNHEALTHY BACKEND FUNCTION: ERROR IN RETRIEVING VNIC ATTACHMENT "+repr(e))
            return None

        vnics = [self.virtualNetworkClient.get_vnic(va.vnic_id).data for va in vnic_attachments]
        try:
            for vnic in vnics:
                if vnic.display_name == insideInterfaceName:
                    ip_response = vnic.private_ip
                    interface_ip.update({'inside_ip': ip_response})
                        
                elif vnic.display_name == outsideInterfaceName:
                    ip_response = vnic.private_ip
                    interface_ip.update({'outside_ip': ip_response})
                        
        except Exception as e:
            logger.error("REMOVE UNHEALTHY BACKEND FUNCTION: ERROR IN RETRIEVING INTERFACES IP ADDRESS "+repr(e))
            return None
        
        logger.debug("REMOVE UNHEALTHY BACKEND FUNCTION: Retrieved Interfaces IP Successfully")
        return interface_ip

    def get_management_public_ip(self, compartmentId, instanceId):
        """
        Purpose:    
        Parameters:
        Returns:    Dict
                    Example: {'management_public_ip': '54.88.96.211'}
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
                logger.error("REMOVE UNHEALTHY BACKEND FUNCTION: ERROR IN RETRIEVING MANAGEMENT PUBLIC IP "+"RETRY COUNT:"+str(i)+"  "+ repr(e))
                continue
        
        return None

    def remove_backend_from_load_balancer(self, lbName, loadBalancerId, backedSetName, ipAddr, portNo):
        """
        Purpose:    Removes particular backend server from the Load Balancer
        Parameters: Load Balancer OCID, Load Balancer Backend Set Name, IP Addr, Port No)
        Returns: None
        Raises: 
        """
        try:
            remove_backend_from_load_balancer_response = self.loadBalancerClient.delete_backend(
                load_balancer_id = loadBalancerId,
                backend_set_name = backedSetName,
                backend_name = str(str(ipAddr)+':'+str(portNo))).data
            
            logger.info("REMOVE UNHEALTHY BACKEND FUNCTION: {0} BACKEND REMOVED SUCCESSFULLY FOR LISTENER PORT NO: {1}".format(lbName,portNo))
            return True

        except Exception as e:
            logger.error("REMOVE UNHEALTHY BACKEND FUNCTION: ERROR IN REMOVING {0} BACKEND FROM LOAD BALANCER FOR LISTENER PORT NO: {1} ERROR: {2}".format(lbName, portNo, repr(e)))
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
    

def handler(ctx, data: io.BytesIO = None):
    try:
        environmentVariables = ctx.Config()        
        ELB_Id = environmentVariables["elb_id"]
        ELB_BackendSetName = environmentVariables["elb_backend_set_name"]
        ELB_ListenerPortNumber = (environmentVariables["elb_listener_port_no"])
        outsideInterfaceName = environmentVariables["outside_interface_name"]
        compartmentId = environmentVariables["compartment_id"]
        instancePoolId = environmentVariables["instance_pool_id"]
        insideInterfaceName = environmentVariables["inside_interface_name"]
        ILB_Id = environmentVariables["ilb_id"]
        ILB_BackendSetName = environmentVariables["ilb_backend_set_name"]
        ILB_ListenerPortNumber = (environmentVariables["ilb_listener_port_no"])
        minInstanceCount = int(environmentVariables["min_instance_count"])
        asavEncryptedPassword = environmentVariables["encrypted_password"]
        cryptEndpoint = environmentVariables["cryptographic_endpoint"]
        master_key_id = environmentVariables["master_key_id"]

    except Exception as e:
        logger.error("REMOVE UNHEALTHY BACKEND FUNCTION: ERROR IN RETRIEVING ENVIRONMENT VARIABLES: "+repr(e))
        return None

    try:
        signer = oci.auth.signers.get_resource_principals_signer()
    except Exception as e:
        logger.error("REMOVE UNHEALTHY BACKEND FUNCTION: ERROR IN OBTAINING SIGNER: "+repr(e))
        return None

    # RemoveBackend Class Object
    removeBackendObject = RemoveBackend(signer)

    ################################ ELB's Unhealthy Backend ###############################
    try:
        elb_unhealthy_backends_response = removeBackendObject.get_unhealthy_backends(ELB_Id, ELB_BackendSetName)
        if elb_unhealthy_backends_response == None:
            logger.error("REMOVE UNHEALTHY BACKEND FUNCTION: Health-Check Action Failed")
            return "Health-Check Action Failed"

        elb_critical_backends = elb_unhealthy_backends_response.critical_state_backend_names
        elb_unknown_backends = elb_unhealthy_backends_response.unknown_state_backend_names
        elb_warning_state_backends = elb_unhealthy_backends_response.warning_state_backend_names

    except Exception as e:
        logger.info("REMOVE UNHEALTHY BACKEND FUNCTION: ERROR IN RETRIEVING UNHEALTHY BACKEND OF ELB  "+repr(e))
        return "Health-Check Action Failed"

    ################################# ILB's Unhealthy Backend ###############################
    try:
        ilb_unhealthy_backends_response = removeBackendObject.get_unhealthy_backends(ILB_Id, ILB_BackendSetName)
        if ilb_unhealthy_backends_response == None:
            logger.error("REMOVE UNHEALTHY BACKEND FUNCTION: Health-Check Action Failed")
            return "Health-Check Action Failed"

        ilb_critical_backends = ilb_unhealthy_backends_response.critical_state_backend_names
        ilb_unknown_backends = ilb_unhealthy_backends_response.unknown_state_backend_names
        ilb_warning_state_backends = ilb_unhealthy_backends_response.warning_state_backend_names
        
    except Exception as e:
        logger.info("REMOVE UNHEALTHY BACKEND FUNCTION: ERROR IN RETRIEVING UNHEALTHY BACKEND OF ILB"+repr(e))
        return "Health-Check Action Failed"

    elb_critical_ip = list(set([ebackend.split(":")[0] for ebackend in elb_critical_backends]))
    ilb_critical_ip = list(set([ibackend.split(":")[0] for ibackend in ilb_critical_backends]))
    
    ################################ GETTING OCID OF TERMINATING INSTANCE ##################################### 
    unhealthy_instance_to_remove = []
    try:
        all_instances_in_pool = removeBackendObject.get_all_instances_in_pool(compartmentId, instancePoolId)
        currentRunningInstanceList = []
        for instance in all_instances_in_pool:
            if instance.state == "Running":
                interface_ip_response = removeBackendObject.get_instance_interface_ip(compartmentId, instance.id, insideInterfaceName, outsideInterfaceName)

                if interface_ip_response["outside_ip"] in elb_critical_ip:
                    unhealthy_instance_to_remove.append(instance.id)
                    elb_critical_ip.remove(interface_ip_response["outside_ip"])

                elif interface_ip_response["inside_ip"] in ilb_critical_ip:
                    unhealthy_instance_to_remove.append(instance.id)
                    ilb_critical_ip.remove(interface_ip_response["inside_ip"])

        logger.info("REMOVE UNHEALTHY BACKEND FUNCTION: Instance going to be terminated : {0}".format(unhealthy_instance_to_remove))
    except Exception as e:
        logger.error("REMOVE UNHEALTHY BACKEND FUNCTION: ERROR IN RETRIEVING UNHEALTHY BACKEND INSTANCE ID "+repr(e))
    #=======================================================================================================#
    ilb_listener_port_list = list(map(lambda x: int(x.strip()), ILB_ListenerPortNumber.split(',')))
    elb_listener_port_list = list(map(lambda x: int(x.strip()), ELB_ListenerPortNumber.split(',')))

    # Removing stale entries if any. (Backends whose instance got deleted somehow but entries wasn't removed from the load balancer)
    if len(elb_critical_ip) > 0:
        logger.info("REMOVE UNHEALTHY BACKEND FUNCTION: CLEARING ELB STALE BACKENDS {}".format(elb_critical_ip))
        for elb_stale_ip in elb_critical_ip:
            for ePort in elb_listener_port_list:
                stale_remove_response = removeBackendObject.remove_backend_from_load_balancer("ELB", ELB_Id, ELB_BackendSetName, elb_stale_ip, ePort)
            logger.info("REMOVE UNHEALTHY BACKEND FUNCTION: STALE BACKEND: {} HAS BEEN REMOVED FROM ELB".format(elb_stale_ip))

    if len(ilb_critical_ip) > 0:
        logger.info("REMOVE UNHEALTHY BACKEND FUNCTION: CLEARING ILB STALE BACKENDS {}".format(ilb_critical_ip))
        for ilb_stale_ip in ilb_critical_ip:
            for iPort in ilb_listener_port_list:
                remove_from_Ilb_response = removeBackendObject.remove_backend_from_load_balancer("ILB", ILB_Id, ILB_BackendSetName, ilb_stale_ip, iPort)
            logger.info("REMOVE UNHEALTHY BACKEND FUNCTION: STALE BACKEND: {} HAS BEEN REMOVED FROM ILB".format(ilb_stale_ip))

    if len(unhealthy_instance_to_remove) == 0:
        logger.info("REMOVE UNHEALTHY BACKEND FUNCTION: NO UNHEALTHY BACKEND FOUND")
        return "NO UNHEALTHY BACKEND FOUND"

    logger.info(f"REMOVE UNHEALTHY BACKEND FUNCTION: Unhealthy Instances going to be terminated are {unhealthy_instance_to_remove}")

    for instanceId in unhealthy_instance_to_remove:
        
        ################################### REMOVING BACKEND FROM LOAD BALANCER ##############################
        instance_interface_ip = removeBackendObject.get_instance_interface_ip(compartmentId, instanceId, insideInterfaceName, outsideInterfaceName)
        if instance_interface_ip == None:
            return None
        
        insideInterfaceIp = instance_interface_ip['inside_ip']
        outsideInterfaceIp = instance_interface_ip['outside_ip']
        
        for ePort in elb_listener_port_list:
            try:
                remove_from_ELB_response = removeBackendObject.remove_backend_from_load_balancer("ELB", ELB_Id, ELB_BackendSetName, outsideInterfaceIp, ePort)
            except Exception in e:
                logger.info("REMOVE UNHEALTHY BACKEND FUNCTION: ERROR IN REMOVING BACKEND FROM ELB  {}".format(e))
                continue
        
        for iPort in ilb_listener_port_list:
            try:
                remove_from_Ilb_response = removeBackendObject.remove_backend_from_load_balancer("ILB", ILB_Id, ILB_BackendSetName, insideInterfaceIp, iPort)
            except Exception in e:
                logger.info("REMOVE UNHEALTHY BACKEND FUNCTION: ERROR IN REMOVING BACKEND FROM ILB  {}".format(e))
                continue 
        #===================================================================================================#
        ##################################### DE-REGISTERING THE LICENSE #################################### 
        try:    
            management_public_ip = removeBackendObject.get_management_public_ip(compartmentId, instanceId)
            if management_public_ip != None:
                asavPassword = removeBackendObject.decrypt_cipher(asavEncryptedPassword, cryptEndpoint, master_key_id)
                asav = ASAvInstance(management_public_ip, asavPassword)
                asav_ssh_status = asav.poll_asav_ssh(4)
                if asav_ssh_status == "SUCCESS":
                    for i in range(0,3):
                        deregister_license_response = asav.deregister_smart_license()
                        if deregister_license_response == "SUCCESS":
                            logger.info("REMOVE UNHEALTHY BACKEND FUNCTION: LICENSE DE-REGISTERED SUCCESSFULLY")
                            break
            
        except Exception as e:
            logger.error("REMOVE UNHEALTHY BACKEND FUNCTION: ERROR IN VERIFICATION OF DE-REGISTERING SMART LICENSE  "+repr(e))
        #====================================================================================================#
        ######################################### TERMINATING THE INSTANCE ##################################
        try:
            terminate_instance_response = removeBackendObject.terminate_instance(instanceId)
            if terminate_instance_response == None:
                logger.error("REMOVE UNHEALTHY BACKEND FUNCTION: ERROR IN TERMINATING INSTANCE")
            else:
                logger.info("REMOVE UNHEALTHY BACKEND FUNCTION: UNHEALTHY INSTANCE HAS BEEN REMOVED")
        except Exception as e:
            logger.info("REMOVE UNHEALTHY BACKEND FUNCTION: ERROR IN TERMINATING INSTANCE  "+repr(e))

    return response.Response(
        ctx, response_data=json.dumps(
            {"REMOVE UNHEALTHY BACKEND FUNCTION Response": "SUCCESSFUL"}),
        headers={"Content-Type": "application/json"}
    )
