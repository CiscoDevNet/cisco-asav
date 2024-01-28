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

logging.getLogger("paramiko").setLevel(logging.WARNING)
logger = logging.getLogger()

class ParamikoSSH:
    """
        This Python class supposed to handle interactive SSH session
    """
    def __init__(self, server, port=22, username='admin'):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.load_system_host_keys()
        self.port = port
        self.server = server
        self.username = username
        self.timeout = 60
        self.SUCCESS = 'SUCCESS'
        self.FAIL = 'FAILURE'
        self.AUTH_EXCEPTION = 'Authentication Exception Occurred'
        self.BAD_HOST_KEY_EXCEPTION = 'Bad Key Exception occurred'
        self.SSH_EXCEPTION = 'SSH Exception Occurred'
        self.identifier = ''
        self.retry = 5

    def close(self):
        self.ssh.close()

    def verify_server_ip(self):
        try:
            socket.inet_aton(self.server)
            return self.SUCCESS
        except socket.error as e:
            logger.error(f"CONFIGURE ASAv {self.identifier}: verify_server_ip Exception occurred: {repr(e)}")
            return self.FAIL
        except Exception as e:
            logger.error(f"CONFIGURE ASAv {self.identifier}: verify_server_ip Exception occurred: {repr(e)}")
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
                self.ssh.connect(self.server, self.port, username, password, timeout=self.timeout, banner_timeout=60, auth_timeout=self.timeout)
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

    def invoke_interactive_shell(self):
        """
        Purpose:    Performs an interactive shell action
        Parameters:
        Returns:    a new Channel connected to the remote shell
        """
        try:
            shell = self.ssh.invoke_shell()
        except paramiko.SSHException as exc:
            logger.error(f"CONFIGURE ASAv {self.identifier}: (invoke_interactive_shell) Exception occurred: {repr(exc)}")
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
            raise ValueError(f"CONFIGURE ASAv {self.identifier}: (handle_interactive_session) Unable to connect to server")
        status, shell = self.invoke_interactive_shell()
        if status != self.SUCCESS:
            raise ValueError(f"CONFIGURE ASAv {self.identifier}: (handle_interactive_session) Unable to invoke shell")
        if self.send_cmd_and_wait_for_execution(shell, '\n') is not None:
            for key in command_set:
                set = command_set[key]
                for i in range(0, len(set)):
                    command = set[i]['command'] + '\n'
                    expect = set[i]['expect']
                    if self.send_cmd_and_wait_for_execution(shell, command, expect) is None:
                        #raise ValueError(f"CONFIGURE ASAv {self.identifier}: (handle_interactive_session) Unable to execute command {command}")
                        pass
        else:
            raise ValueError(f"CONFIGURE ASAv {self.identifier}: (handle_interactive_session) Unable to execute command \\n")

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
        try:
            shell.send(command)
            while wait_string not in rcv_buffer.decode("utf-8"):
                rcv_buffer = shell.recv(10000)
                total_msg = total_msg + ' ' + rcv_buffer.decode("utf-8")
            logger.debug(f"CONFIGURE ASAv {self.identifier}: Command Output: {total_msg}")
            return total_msg
        except Exception as e:
            logger.error(f"CONFIGURE ASAv {self.identifier}:send_cmd_and_wait_for_execution: Command:{repr(command)}, Wait string:{wait_string}, Buffer: {total_msg} ERROR:{repr(e)}")
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
        self.identifier = ''

    def connect_asa(self):
        """
        Purpose:    This provides object of ParamikoSSH class
        Parameters:
        Returns:    Class object, None
        Raises:
        """

        connect = ParamikoSSH(self.ip_to_connect, self.port, self.username)
        connect.identifier = self.identifier
        logger.debug(connect)
        return connect

    # function to change password(admin) from prev_password to new_password
    def change_asa_password(self, new_password):
        """
        Purpose:    To change password from default to user provided
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        prev_password = self.defaultPassword
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
            cnt_asa = self.connect_asa()
            change_password_response = cnt_asa.handle_interactive_session(command_set, self.username, prev_password)
        except ValueError as e:
            logger.error(f"CONFIGURE ASAv {self.identifier}: (change_asa_password) Error occurred: {repr(e)}")
            return self.FAIL
        else:
            return self.SUCCESS
        finally:
            cnt_asa.close()
            time.sleep(6)

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
            cnt_asa.close()
            return self.SUCCESS
        elif status == 'Authentication Exception Occurred':
            logger.info(f"CONFIGURE ASAv {self.identifier}: Trying SSH connection using default password")
            status = cnt_asa.connect(self.username, self.defaultPassword)
            if status == 'SUCCESS':
                cnt_asa.close()
                return 'SUCCESS_DEFAULT'
        cnt_asa.close()
        return 'FAILURE'

    # Polling connectivity to FTDv for specified 'minutes'
    def poll_asav_ssh(self, minutes, begin_time):
        """
        Purpose:    To poll ASAv for SSH accessibility
        Parameters: Minutes
        Returns:    SUCCESS, TIMEOUT
        Raises:
        """
        logger.info(f"CONFIGURE ASAv {self.identifier}: Checking if instance SSH access is available!")
        if minutes < 1:
            minutes = 1
        for i in range(1, (6 * minutes)+1):
                status = self.check_asav_ssh_status()
                if status == "FAILURE":
                    time_spent = int(time.time())-begin_time
                    if (time_spent > 230):
                        logger.error(f"CONFIGURE ASAv {self.identifier}: SSH POLLING PASSED DEFINED TIME LIMIT {time_spent}")
                        return "TIMEOUT"
                    logger.info(f"CONFIGURE ASAv {self.identifier}: Unable to get SSH Connection, Retry:{str(i)}, Retrying in 10 seconds")
                    time.sleep(1 * 10)
                else:
                    return status
        logger.error(f"CONFIGURE ASAv {self.identifier}: FAILED TO CREATE SSH CONNECTION AFTER ALL RETRIES")
        return "TIMEOUT"

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

        logger.debug("Executing commands: " + cmd1)
        logger.debug("Executing commands: " + cmd2)
        cnt_asa = self.connect_asa()
        try:
            cnt_asa.handle_interactive_session(command_set, self.username, self.password)
        except ValueError as e:
            logger.error(f"CONFIGURE ASAv {self.identifier}: (run_copy_file_running_config) Error occurred: {repr(e)}")
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
        cnt_asa = self.connect_asa()
        try:
            cnt_asa.handle_interactive_session(command_set, self.username, self.password)
        except ValueError as e:
            logger.error(f"CONFIGURE ASAv {self.identifier}: (one_time_interface_configuration) Error occurred: {repr(e)}")
            return None
        else:
            return 'SUCCESS'
        finally:
            cnt_asa.close()
            time.sleep(6)

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
            logger.error(f"CONFIGURE ASAv {self.identifier}: (configure_hostname) Error occurred: {repr(e)}")
            return self.FAIL
        else:
            return self.SUCCESS
        finally:
            cnt_asa.close()
            time.sleep(6)

class ConfigureASAv:
    def __init__(self, compartmentId):
        self.signer = oci.auth.signers.get_resource_principals_signer()
        self.computeClient = oci.core.ComputeClient(config={}, signer=self.signer)
        self.ons_client = oci.ons.NotificationDataPlaneClient(config={}, signer=self.signer)
        self.compartmentId = compartmentId
        self.identifier = ''
        self.retries = 3

    def decrypt_cipher(self, cipherText, cryptEndpoint, keyId):
        """
        Purpose:   To decrypt encrypted password.
        Parameters: Encrypted Password, Cryptographic Endpoint, Master Key OCID
        Returns:    password in plaintext (str)
        Raises:
        """
        for i in range(0,self.retries):
            try:
                key_management_client = oci.key_management.KmsCryptoClient(config={}, signer=self.signer, service_endpoint = cryptEndpoint)

                decrypt_response = key_management_client.decrypt(
                    decrypt_data_details=oci.key_management.models.DecryptDataDetails(
                        ciphertext = cipherText,
                        key_id = keyId)).data

                return base64.b64decode(decrypt_response.plaintext).decode('utf-8')
            except Exception as e:
                logger.error(f"CONFIGURE ASAv {self.identifier}: ERROR IN DECRYPTING PASSWORD ERROR: {repr(e)}")
                continue
        return None

    def publish_message(self, topicId, msg):
        """
        Purpose:   To publish message to OCI Notification.
        Parameters: Topic ID, Message
        Returns:    Bool
        Raises:
        """
        for i in range(0, self.retries):
            try:
                publish_message_response = self.ons_client.publish_message(
                    topic_id = topicId,
                    message_details=oci.ons.models.MessageDetails(
                        body = json.dumps(msg),
                        title = "Configure_ASAv_Recall")).data
                return True
            except Exception as e:
                logger.info(f"CONFIGURE ASAv {self.identifier}: ERROR:{repr(e)}")
                continue
        return False

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

                logger.info(f"CONFIGURE ASAv {self.identifier}: INSTANCE TERMINATED AS SOMETHING WENT WRONG, PLEASE CHECK PREVIOUS LOGS")
                return True

            except Exception as e:
                logger.info(f"CONFIGURE ASAv {self.identifier}: ERROR OCCURRED WHILE TERMINATING INSTANCE, RETRY COUNT:{str(i+1)}, REASON:{repr(e)}")
                continue
        return False

def handler(ctx, data: io.BytesIO=None):
    """
    Purpose:   Main Function, receive JSON payload, Environmental Variable, implementation logic.
    Parameters: ctx (Contains Environmental Variables passed), data (Json Payload emit by event which called this function)
    Returns:    Response
    Raises:
    """
    #__________________________________________________________________________________________________________
    # READING PAYLOAD
    try:
        body = json.loads(data.getvalue())
        instanceId = body.get("instance_id")
        insideInterfaceIpAddress = body.get("inside_interface_ip")
        outsideInterfaceIpAddress = body.get("outside_interface_ip")
        insideSubnetNetmask = body.get("inside_subnet_netmask")
        outsideSubnetNetmask = body.get("outside_subnet_netmask")
        management_public_ip = body.get("management_public_ip")
        counter = int(body.get("counter"))
        identifier = instanceId[-5:]
        begin_time = int(time.time())
        logger.info(f"{identifier}---- CONFIGURE ASAv CALLED {counter} -----")
    except Exception as ex:
        logger.error("CONFIGURE ASAv: ERROR IN PARSING JSON PAYLOAD, PLEASE MANUALLY DELETE THE INSTANCE FOR WHICH IT FAILED: " + repr(ex))
        return "CONFIGURE ASAv: ERROR IN PARSING JSON PAYLOAD"

    # READING ENVIRONMENT VARIABLES
    try:
        environmentVariables = ctx.Config()
        compartmentId = environmentVariables["compartment_id"]
        outsideInterfaceName = environmentVariables["outside_interface_name"]
        instancePoolId = environmentVariables["instance_pool_id"]
        insideInterfaceName = environmentVariables["inside_interface_name"]
        configuration_file_url = environmentVariables["configuration_file_url"]
        asavEncryptedPassword = environmentVariables["encrypted_password"]
        cryptEndpoint = environmentVariables["cryptographic_endpoint"]
        master_key_id = environmentVariables["master_key_id"]
        topicId = environmentVariables["configure_asav_topic_id"]
        log_level = environmentVariables["log_level"] # Set to DEBUG in function environment variabled for detailed logs.
    except Exception as e:
        logger.error(f"CONFIGURE ASAv {identifier}: ERROR IN RETRIEVING ENVIRONMENT VARIABLES ERROR: {repr(e)}")
        return "CONFIGURE ASAv FAILED WITH THIS INSTANCE"
    
    # SETING LOG LEVEL
    try:
        if log_level == "DEBUG":
            logging.basicConfig(force=True, level="DEBUG")
        else:
            logging.basicConfig(force=True, level="INFO")
    except Exception as e:
        logger.error(f"CONFIGURE ASAv {identifier}: ERROR IN SETTING LOG LEVEL")
        logging.basicConfig(force=True, level="INFO")
    finally:
        logging.getLogger("paramiko").setLevel(logging.WARNING)
    
    #__________________________________________________________________________________________________________
    # GETTING THE CONFIGURE ASAv OBJECT
    configASAObject = ConfigureASAv(compartmentId)
    configASAObject.identifier = identifier

    # COUNTER MANAGEMENT
    body["counter"] = counter+1

    MAX_RECALL = 5 # Maximum number of time function will be recalled.
    if counter > MAX_RECALL:
        logger.critical(f"CONFIGURE ASAv {identifier}: MAX RECALL HAS REACHED, FAILED TO CONFIGURE ASAv, INSTANCE WILL BE TERMINATED")
        configASAObject.terminate_instance(instanceId)
        return "MAX RECALL REACHED"
    #__________________________________________________________________________________________________________
    # CONFIGURING ASAV VIA SSH
    try:
        # DECRYPTING PASSWORD
        asavPassword = configASAObject.decrypt_cipher(asavEncryptedPassword, cryptEndpoint, master_key_id)

        # OBTAINING ASAv OBJECT
        asav = ASAvInstance(management_public_ip, asavPassword)
        asav.identifier = identifier

        # POLLING FOR SSH
        asav_ssh_status = asav.poll_asav_ssh(2,begin_time)
        if asav_ssh_status == 'TIMEOUT':
            logger.error(f"CONFIGURE ASAv {identifier}: NOT ABLE TO GET SSH ON ASAV, WILL RECALL")
            configASAObject.publish_message(topicId, body)
            return "UNABLE TO OBTAIN SSH"

        if asav_ssh_status == "SUCCESS_DEFAULT":
            # UPDATING THE DEFAULT PASSWORD
            update_password_response = asav.change_asa_password(asavPassword)
            if update_password_response == 'SUCCESS':
                logger.info(f"CONFIGURE ASAv {identifier}: Password changed succesfully")
            else:
                logger.error(f"CONFIGURE ASAv {identifier}: UNABLE TO AUTHENTICATE TO ASAv INSTANCE, RECALLING")
                configASAObject.publish_message(topicId, body)
                return "RECALLING"

        if (int(time.time())-begin_time > 250):
            logger.error(f"CONFIGURE ASAv {identifier}: FUNCTION TIMEOUT LIMIT TEACHING (1), RECALLING")
            configASAObject.publish_message(topicId, body)
            return "RECALLING"
        
        # CONFIGURING INTERFACES
        one_time_interface_configuration_response = asav.one_time_interface_configuration(insideInterfaceIpAddress, insideSubnetNetmask, outsideInterfaceIpAddress,outsideSubnetNetmask)
        if one_time_interface_configuration_response != "SUCCESS":
            logger.info(f"CONFIGURE ASAv {identifier}: ERROR OCCURRED IN INTERFACE CONFIGURATION")
            configASAObject.publish_message(topicId, body)
            return "RECALLING"
        else:
            logger.info(f"CONFIGURE ASAv {identifier}: Interfaces have been configured successfully")

        if (int(time.time())-begin_time > 250):
            logger.error(f"CONFIGURE ASAv {identifier}: FUNCTION TIMEOUT LIMIT TEACHING (2), RECALLING")
            configASAObject.publish_message(topicId, body)
            return "RECALLING"
        
        # CONFIGURING HOSTNAME
        vm_name = "ciscoasa-" + identifier
        hostname_response = asav.configure_hostname(vm_name)
        logger.info(f"CONFIGURE ASAv {identifier}: ASAv instance Hostname configuration response {hostname_response}")

        if (int(time.time())-begin_time > 270):
            logger.error(f"CONFIGURE ASAv {identifier}: FUNCTION TIMEOUT LIMIT TEACHING (3), RECALLING")
            configASAObject.publish_message(topicId, body)
            return "RECALLING"

        # COPYING CONFIGURATION FILE TO ASAv
        asav_configuration_file_local_path = 'disk0:configuration.txt'
        asav_response = asav.run_copy_file_running_config(configuration_file_url, asav_configuration_file_local_path)
        if asav_response != 'SUCCESS':
            logger.error(f"CONFIGURE ASAv {identifier}: FAILED TO COPY CONFIGURATION.TXT FILE, RECALLING")
            configASAObject.publish_message(topicId, body)
            return "RECALLING"
        else:
            logger.info(f"CONFIGURE ASAv {identifier}: Configure ASAv action performed successfully for instance {instanceId}")
    #__________________________________________________________________________________________________________
    except Exception as e:
        logger.critical(f"CONFIGURE ASAv {identifier}: ERROR IN CONFIGURE ASAV "+repr(e))
        configASAObject.publish_message(topicId, body)
        return "RECALLING"

    return response.Response(
        ctx, response_data=json.dumps(
            {"Response": "Configure ASAv performed successfully"}),
        headers={"Content-Type": "application/json"})