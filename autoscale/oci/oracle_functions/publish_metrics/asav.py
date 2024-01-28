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
            These classes will be initialized in oracle function as needed
"""

import os
import time
import paramiko
import json
import socket
import constants as const

# Setup Logging
import sys
import logging
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

logger = setup_logging('enable')


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
        self.retry = 5

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
            self.ssh.connect(self.server, self.port, username, password, timeout=60, banner_timeout=60, auth_timeout=60, allow_agent= False, look_for_keys= False)
            logger.debug("Connection to %s on port %s is successful!" % (self.server, self.port))
            return self.SUCCESS
        except paramiko.AuthenticationException as exc:
            logger.error("Exception occurred: {}".format(repr(exc)))
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

        if self.connect(username, password) != self.SUCCESS:
            logger.error("Unable to connect to server")
            return self.FAIL
        status, shell = self.invoke_interactive_shell()
        if status != self.SUCCESS:
            logger.error("Unable to invoke shell")
            return self.FAIL
        if self.send_cmd_and_wait_for_execution(shell, '\n') is not None:
            for key in command_set:
                set = command_set[key]
                for i in range(0, len(set)):
                    command = set[i]['command'] + '\n'
                    expect = set[i]['expect']
                    output = self.send_cmd_and_wait_for_execution(shell, command, expect)
                    logger.info("Output : {}".format(output))
                    if output is not None:
                        if "CPU utilization" in output:
                            self.ssh.close()
                            return output
                        pass
                    else:
                        self.ssh.close()
                        logger.error(f"Unable to execute command: {command}")
                        return self.FAIL
        self.ssh.close()
        return self.FAIL

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
                if shell.recv_ready():
                    rcv_buffer = shell.recv(10000)
                    total_msg = total_msg + ' ' + rcv_buffer.decode("utf-8")
            logger.debug(f"Interactive SSH Output: {total_msg}")
            return total_msg
        except Exception as e:
            logger.error(f" (send_cmd_and_wait_for_execution): Command:{repr(command)}, Wait string:{wait_string}, Buffer: {total_msg} ERROR:{repr(e)}")
            return None
