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

Name:       asav.py
Purpose:    This python file has ASAv related class & methods
            These classes will be initialized in Lambda function as needed
"""

import os
import time
import paramiko
import json
import socket
import constant as const
import utility as utl
from aws import CiscoEc2Instance

# Setup Logging
logger = utl.setup_logging(os.environ['DEBUG_LOGS'])


class ASAvInstance(CiscoEc2Instance):
    """
        This is ASAv class, supposed to instantiated only in Configure_ASAv Lambda function
    """
    def __init__(self, instance_id):
        # Get User input, works only for Configure_ASAv Lambda function
        self.user_input = utl.get_user_input_configure_asav()
        # Inherit CiscoEc2Instance class
        super().__init__(instance_id)
        self.public_ip = self.get_public_ip()
        self.private_ip = self.get_private_ip()
        self.port = const.ASAV_SSH_PORT
        self.username = const.ASAV_USERNAME
        self.defaultPassword = const.DEFAULT_PASSWORD
        self.password = self.user_input['AutoScaleUserPassword']
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
        if const.USE_PUBLIC_IP_FOR_SSH and self.public_ip is not None:
            # To SSH ASAv Public IP
            ip_to_connect = self.public_ip
        else:
            if self.private_ip is not None:
                # To SSH ASAv Private IP
                ip_to_connect = self.private_ip
            else:
                logger.error("Found None for private_ip of the ASAv instance")
                return None

        connect = ParamikoSSH(ip_to_connect, self.port, self.username, self.password)
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
            logger.error("Error occurred: {}".format(repr(e)))
            return self.FAIL, output, error
        if status == self.SUCCESS:
            logger.debug("%s %s %s" % (self.COMMAND_RAN, output, error))
            return self.COMMAND_RAN, output, error
        else:
            logger.warn("Unable to run command output: %s error: %s" % (output, error))
            return self.FAIL, output, error

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
        elif status == 'Authentication Exception Occurred':
            status = cnt_asa.connect(self.username, self.defaultPassword)
            if status == 'SUCCESS':
                cnt_asa.close()  # As below function triggers interactive shell
                if self.change_asa_password(cnt_asa, self.defaultPassword, self.password) == 'SUCCESS':
                    return 'SUCCESS'
            else:
                logger.error("Unable to authenticate to ASAv instance, please check password!")
                return 'FAILURE'
        return 'FAILURE'

    # Polling connectivity to FTDv for specified 'minutes'
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
        for i in range(1, 2 * minutes):
            if i != ((2 * minutes) - 1):
                status = self.check_asav_ssh_status()
                if status != "SUCCESS":
                    logger.debug(str(i) + " Sleeping for 30 seconds")
                    time.sleep(1 * 30)
                else:
                    return "SUCCESS"
        logger.info("Failed to connect to device retrying... ")
        return "TIMEOUT"

    # function to set hostname
    def configure_hostname(self):
        """
        Purpose:    To configure hostname on ASAv
        Parameters:
        Returns:    'FAILURE', 'COMMAND_RAN'
        Raises:
        """
        cnt_asa = self.connect_asa()
        cmd = 'hostname ' + self.vm_name
        expected_outcome = self.vm_name + "(config)#"
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
        # logger.info("Initiating hostname change of ASAv with command set: "
        #             + json.dumps(command_set, separators=(',', ':')))
        try:
            cnt_asa.handle_interactive_session(command_set, self.username, self.password)
        except ValueError as e:
            logger.error("Error occurred: {}".format(repr(e)))
            return self.FAIL
        else:
            return self.SUCCESS

    def get_sn_of_asav(self):
        """
        Purpose:    To get SN of ASAv
        Parameters:
        Returns:    Either SN or N/A
        Raises:
        """
        try:
            command = "show version | include .*[Ss]erial.[Nn]umber:.* " + "\n"
            status, output, error = self.run_asav_command(command)
            output_json = {
                "command": command,
                "status": status,
                "output": output,
                "error": error
            }
            logger.debug(json.dumps(output_json, separators=(',', ':')))
            output = output.replace(" ", "")
            output_list = output.split(":")
            return output_list[1]
        except IndexError as e:
            logger.debug("Error occurred: {}".format(repr(e)))
            logger.error("Unable to get SN of ASAv")
            return 'N/A'
        except Exception as e:
            logger.error("Error occurred: {}".format(repr(e)))
            return 'N/A'

    # function to change password(admin) from prev_password to new_password
    def change_asa_password(self, cnt_asa, prev_password, new_password):
        """
        Purpose:    To change password from default to user provided
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        write_memory_config = "copy /noconfirm running-config startup-config"
        expected_outcome_write_memory_config = "#"
        change_password_cmd = "change-password old-password " + prev_password + " new-password " + new_password
        change_enable_password_cmd = "enable " + "password " + new_password
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
            logger.error("Error occurred: {}".format(repr(e)))
            return None
        else:
            return 'SUCCESS'
        finally:
            cnt_asa.close()

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
            logger.debug("Error occurred: {}".format(repr(e)))
            # logger.debug("It's likely that verify_string didn't match for command")
            return self.FAIL
        except Exception as e:
            logger.error("Error occurred: {}".format(repr(e)))
            return self.FAIL
        else:
            logger.info("Found String: " + verify_string)
            return self.SUCCESS
        finally:
            cnt_asa.close()

    def verify_configuration_file_copy(self, local_file_name):
        """
        Purpose:    To verify whether configuration file copied or not
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        command = 'show disk0: '
        verify_string = local_file_name
        return self.verify_string_match(command, verify_string)

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

    def verify_asa_license_registering(self):
        """
        Purpose:    To verify smart license in REGISTERING state
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        command = 'show license summary'
        verify_string = 'REGISTERING'
        return self.verify_string_match(command, verify_string)

    def verify_asa_license_authorized(self):
        """
        Purpose:    To verify smart license AUTHORIZED
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        command = 'show license features'
        verify_string = 'enforce mode: Authorized'
        return self.verify_string_match(command, verify_string)

    def verify_aws_licensing(self):
        """
        Purpose:    To verify AWS Licensing
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        command = 'show license features'
        verify_string = 'AWS Licensing'
        return self.verify_string_match(command, verify_string)

    def verify_asav_payg_licensed(self):
        """
        Purpose:    To verify ASAv is Licensed
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        command = 'show license features'
        verify_string = 'License state: LICENSED'
        return self.verify_string_match(command, verify_string)

    def verify_asav_byol_licensed(self):
        """
        Purpose:    To verify ASAv is Licensed
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        command = 'show license features'
        verify_string = 'ASAv Platform License State: Licensed'
        return self.verify_string_match(command, verify_string)

    def verify_asa_smart_licensing_enabled(self):
        """
        Purpose:    To verify smart license ENABLED
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        command = 'show license features'
        verify_string = 'License mode: Smart Licensing'
        return self.verify_string_match(command, verify_string)

    def verify_at_least_one_nat_policy_present(self):
        """
        Purpose:    To verify if at least one NAT policy present
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        command = 'show nat'
        verify_string = 'translate_hits'
        return self.verify_string_match(command, verify_string)

    def poll_asa_license_authorized(self, minutes):
        """
        Purpose:    To poll ASAv for Licensing
        Parameters: Minutes
        Returns:    SUCCESS, TIMEOUT
        Raises:
        """
        logger.info("Checking if instance license is AUTHORIZED")
        if minutes <= 1:
            minutes = 2
        for i in range(1, 2 * minutes):
            if i != ((2 * minutes) - 1):
                status = self.verify_asa_license_authorized()
                if status != "SUCCESS":
                    logger.debug(str(i) + " Sleeping for 15 seconds")
                    time.sleep(1 * 15)
                else:
                    return "SUCCESS"
        return "TIMEOUT"

    # fixme This operation is inconsistent hence NOT SUPPORTED,
    #  Any breakage in Communication, can cause ASAv to be terminated without de-register license.
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
            logger.error("Error occurred: {}".format(repr(e)))
            return self.FAIL
        else:
            return self.SUCCESS
        finally:
            cnt_asa.close()

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
        logger.info("Executing commands: " + cmd1)
        logger.info("Executing commands: " + cmd2)
        cnt_asa = self.connect_asa()
        try:
            cnt_asa.handle_interactive_session(command_set, self.username, self.password)
        except ValueError as e:
            logger.error("Error occurred: {}".format(repr(e)))
            return None
        else:
            return 'SUCCESS'
        finally:
            cnt_asa.close()


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
            logger.error("Exception occurred: {}".format(repr(e)))
            return self.FAIL
        except Exception as e:
            logger.error("Exception occurred: {}".format(repr(e)))
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
            self.ssh.connect(self.server, self.port, username, password, timeout=10)
            logger.debug("Connection to %s on port %s is successful!" % (self.server, self.port))
            return self.SUCCESS
        except paramiko.AuthenticationException as exc:
            logger.warn("Exception occurred: {}".format(repr(exc)))
            return self.AUTH_EXCEPTION
        except paramiko.BadHostKeyException as exc:
            logger.debug("Exception occurred: {}".format(repr(exc)))
            return self.BAD_HOST_KEY_EXCEPTION
        except paramiko.SSHException as exc:
            logger.debug("Exception occurred: {}".format(repr(exc)))
            return self.SSH_EXCEPTION
        except BaseException as exc:
            logger.debug("Exception occurred: {}".format(repr(exc)))
            return self.FAIL

    def execute_cmd(self, command):
        """
        Purpose:    Performs an interactive shell action
        Parameters: Command
        Returns:    action status, output & error
        """
        if self.connect(self.username, self.password) != self.SUCCESS:
            raise ValueError("Unable to connect to server")
        try:
            ssh_stdin, ssh_stdout, ssh_stderr = self.ssh.exec_command(command, timeout=30)
        except paramiko.SSHException as exc:
            logger.error("Exception occurred: {}".format(repr(exc)))
            self.ssh.close()
            return self.FAIL, None, None
        else:
            output = ssh_stdout.readlines()
            error = ssh_stderr.readlines()
            logger.debug('SSH command output: ' + str(output))
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
            logger.error("Exception occurred: {}".format(repr(exc)))
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
            raise ValueError("Unable to connect to server")
        status, shell = self.invoke_interactive_shell()
        if status != self.SUCCESS:
            raise ValueError("Unable to invoke shell")
        if self.send_cmd_and_wait_for_execution(shell, '\n') is not None:
            for key in command_set:
                set = command_set[key]
                for i in range(0, len(set)):
                    command = set[i]['command'] + '\n'
                    expect = set[i]['expect']
                    if self.send_cmd_and_wait_for_execution(shell, command, expect) is not None:
                        pass
                    else:
                        raise ValueError("Unable to execute command!")
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
                rcv_buffer = str(shell.recv(10000))
            logger.debug("Interactive SSH Output: " + str(rcv_buffer))
            return rcv_buffer
        except Exception as e:
            logger.error("Error occurred: {}".format(repr(e)))
            return None
