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

Name:       asav.py
Purpose:    This python file has ASAv related class & methods
            This class will be initialized in Lambda function as needed
"""

import os
import paramiko
import socket
import json
import time
import utils as util

# Setup Logging
logger = util.setup_logging(os.environ['DEBUG_LOGS'])


class ASAv():
    """
        This is ASAv class, supposed to instantiated only in guardduty event analyser lambda function
    """
    def __init__(self, public_ip, username, password, enable_pw):
        self.public_ip = public_ip
        self.port = 22
        self.username = username
        self.password = password
        self.enable_pw = enable_pw
        self.SUCCESS = 'SUCCESS'
        self.FAIL = 'FAILURE'

    def connect_asa(self):
        """
        Purpose:    This provides object of ParamikoSSH class
        Parameters:
        Returns:    Class object, None
        Raises:
        """

        connect = ParamikoSSH(self.public_ip, self.port, self.username, self.password)
        logger.debug(connect)
        return connect

    def exec_asav_command(self, commands):
        """
        Purpose:    To execute/configure the given CLIs in ASAv
        Parameters: commands - array of CLI's
        Returns: True, if success and error if value error exception
        Raises:
        """
        command_set = {
            "cmd": [
                {
                    "command": "enable",
                    "expect": "Password:"
                },
                {
                    "command": self.enable_pw,
                    "expect": "#"
                },
                {
                    "command": "conf t",
                    "expect": "#"
                }
            ]
        }
        for cmd in commands:
            command_set["cmd"].append({
                    "command": cmd,
                    "expect": "#"
                })
        
        command_set["cmd"].append(
                {
                    "command": "write memory",
                    "expect": "#"
                })
    
        logger.debug("Executing commands: " + cmd)
        
        cnt_asa = self.connect_asa()
        try:
            cnt_asa.handle_interactive_session(command_set, self.username, self.password)
        except ValueError as e:
            logger.debug("Error occurred: {}".format(repr(e)))
            return e
        else:
            return True
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
        """
            Purpose:    To close SSH session
            Parameters:
            Returns:
            Raises:
        """
        self.ssh.close()

    def verify_server_ip(self):

        """
        Purpose:    To verify IP address
        Parameters:
        Returns: returns FAILURE on exception
        Raises:
        """
        try:
            socket.inet_aton(self.server)
            return self.SUCCESS
        except socket.error as e:
            logger.debug("Exception occurred: {}".format(repr(e)))
            return self.FAIL
        except Exception as e:
            logger.debug("Exception occurred: {}".format(repr(e)))
            return self.FAIL

    def connect(self, username, password):
        """
        Purpose:    Opens a connection to server
        Parameters: username and password
        Returns:    Success or failure, if failure then returns specific error
                    self.SUCCESS = 'SUCCESS'
                    self.FAIL = 'FAILURE'
                    self.AUTH_EXCEPTION = 'Authentication Exception Occurred'
                    self.BAD_HOST_KEY_EXCEPTION = 'Bad Key Exception occurred'
                    self.SSH_EXCEPTION = 'SSH Exception Occurred'
        Raises:
        """
        if self.verify_server_ip() == 'FAILURE':
            return self.FAIL
        try:
            self.ssh.connect(self.server, self.port, username, password, timeout=10, look_for_keys=False, allow_agent=False)
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

    def invoke_interactive_shell(self):
        """
        Purpose:    Performs an interactive shell action
        Parameters:
        Returns:    a new Channel connected to the remote shell
        Raises:
        """
        try:
            shell = self.ssh.invoke_shell()
        except paramiko.SSHException as exc:
            logger.debug("Exception occurred: {}".format(repr(exc)))
            self.ssh.close()
            return self.FAIL, None
        else:
            return self.SUCCESS, shell

    def handle_interactive_session(self, command_set, username, password):
        """
        Purpose: Performs an interactive shell action
        Parameters: command_set: a dict of set of commands expressed in command & expect values
        Returns:
        Raises: ValueError based on the error
        """
        if self.connect(username, password) != self.SUCCESS:
            raise ValueError("unable to connect to server")
        status, shell = self.invoke_interactive_shell()
        if status != self.SUCCESS:
            raise ValueError("unable to create ssh session")
        if self.send_cmd_and_wait_for_execution(shell, '\n') is not None:
            for key in command_set:
                set = command_set[key]
                for i in range(0, len(set)):
                    command = set[i]['command'] + '\n'
                    expect = set[i]['expect']
                    if self.send_cmd_and_wait_for_execution(shell, command, expect) is not None:
                        pass
                    else:
                        raise ValueError("unable to execute command")
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
                time.sleep(1)
                rcv_buffer += str(shell.recv(10000))
            logger.debug("Interactive SSH Output: " + str(rcv_buffer))
            return rcv_buffer
        except Exception as e:
            logger.debug("Error occurred when executing command \"{}\", wait string:{}, received buffer:{}, error:{}"
                         .format(command, wait_string, str(rcv_buffer), repr(e)))
            return None
    
    