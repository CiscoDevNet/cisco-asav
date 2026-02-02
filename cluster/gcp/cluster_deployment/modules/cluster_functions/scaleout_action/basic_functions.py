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
Name:       basic_functions.py
Purpose:    This python file has basic functions for 
            SSH and running commands in ASAv.
"""
import paramiko
import time
import os
from google.cloud import secretmanager
import re

def connect_ssh(ip, user, password, minutes):
     print(f"Trying to Login to ASAv: {ip}")
     ssh = paramiko.SSHClient()
     ssh.load_system_host_keys()
     ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
     for i in range(6*minutes):
          try:
               ssh.connect(ip, username=user, password=password, timeout=10)
               channel = ssh.invoke_shell()
               resp = channel.recv(9999)
               print(resp.decode("utf-8"))
               #Please change your password before proceeding.
               if "reset" in resp.decode("utf-8"):
                    cmd = password
                    exec_command(channel,cmd)
                    exec_command(channel,cmd)
                    exec_command(channel,cmd)
                    #3 times because of old, new, re-enter password
               #User admin logged in to ...
               if "User" in resp.decode("utf-8"):
                    return 'SUCCESS',channel,ssh
               time.sleep(10)
          except paramiko.AuthenticationException as exc:
               print("ERROR: Exception occurred: AuthenticationException {}".format(repr(exc)))
               print(str(i)+". Will retry in 10 seconds")
               time.sleep(10)
          except paramiko.BadHostKeyException as exc:
               print("ERROR: Exception(un-known) occurred: BadHostKeyException {}".format(repr(exc)))
               # Keys sync after node joins cluster, need to clear old key.
               ssh.get_host_keys().clear()
               print(str(i)+". Will retry in 10 seconds")
               time.sleep(10)
          except paramiko.SSHException as exc:
               print("ERROR: Exception(un-known) occurred: SSHException {}".format(repr(exc)))
               print(str(i)+". Will retry in 10 seconds")
               time.sleep(10)
          except BaseException as exc:
               #print("Exception(un-known) occurred: BaseException {}".format(repr(exc)))
               print(str(i)+". SSH not available, will retry in 10 seconds. BaseException")
               time.sleep(10)

     print("Timeout after ", minutes, " minutes.")
     return

def response_msg(channel):
     resp = channel.recv(9999) # 9999 is the number of bytes
     return resp.decode("utf-8")

def exec_command(channel,cmd):
     cmd = cmd + "\n"
     channel.send(cmd)
     time.sleep(3)  # 3 sec wait time
     resp = response_msg(channel)
     print(resp)
     return resp
     
def close_shell(ssh):
     ssh.close()

# "enable"
def enable_asa(channel, password):
     try:
          print("Going to EXEC Mode")
          cmd = "enable"
          exec_command(channel,cmd)
          msg = exec_command(channel,password)
          if "Repeat Password" in msg:
               exec_command(channel,password)
          print("Going to Global Config Mode")
          cmd = "configure terminal"
          exec_command(channel, cmd)
          return
     except Exception as e:
          raise Exception("Error occurred: Failed to go to EXEC Mode {}".format(repr(e)))

# write memory
def save_config(channel):
     try:
          print("Saving the Configuration")
          cmd = "write memory"
          exec_command(channel,cmd)
          print("Configuration Saved")
          return
     except Exception as e:
          raise Exception("Error occurred: Failed to save configuration {}".format(repr(e)))

#change SSH Password
def change_ssh_pwd(channel, username, password):
     try:
          print("Changing SSH Password")
          cmd = "username "+username+" password "+password+" privilege 15"
          # do not use exec_command to avoid this on Logs
          cmd = cmd + "\n"
          channel.send(cmd)
          time.sleep(3)  # 3 sec wait time
          resp = response_msg(channel)
          print("Password changed Successfully")
     except Exception as e:
          raise Exception("Error occurred: Failed to update password {}".format(repr(e)))

#change Hostname
def change_hostname(channel):
     try:
          print("Changing Hostname")
          cmd = "hostname asavcluster"
          exec_command(channel,cmd)
          print("Hostname changed Successfully")
     except Exception as e:
          raise Exception("Error occurred: Failed to update hostname {}".format(repr(e)))

def fetch_secret(project_id, secret_id, version_id):
     client = secretmanager.SecretManagerServiceClient()
     name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
     response = client.access_secret_version(request={"name": name})
     return response.payload.data.decode("UTF-8")

def fetch_cluster_status(channel):
    '''
    Purpose:
        Check cluster info
    Arguments:
        * self - ASAv object
    Return:
        * Cluster info
    '''
    cmd = "show cluster info | grep _NODE"
    try:
        msg = exec_command(channel,cmd)
    except Exception as e:
        raise Exception("Error occurred: {}".format(repr(e)))
    else:
        return msg

def verify_string_match(channel, command, verify_string):
     """
     Purpose:    To verify string match
     Parameters: ParamikoSSH class object, Default password, New Password
     Returns:    SUCCESS, None
     Raises:
     """
     print("Running Command: " + command)
     print("Expecting String: " + verify_string)

     cmd = command
     msg = exec_command(channel,cmd)
     print(msg)
     if verify_string in msg:
          return 'SUCCESS'
     return 'FAIL'

def verify_asa_smart_licensing_enabled(channel):
     """
     Purpose:    To verify smart license ENABLED
     Parameters: ParamikoSSH class object, Default password, New Password
     Returns:    SUCCESS, None
     Raises:
     """
     command = 'show license features | grep License'
     verify_string = 'License mode: Smart Licensing'
     return verify_string_match(channel, command, verify_string)

def verify_asav_byol_licensed(channel):
     """
     Purpose:    To verify ASAv is Licensed
     Parameters: ParamikoSSH class object, Default password, New Password
     Returns:    SUCCESS, None
     Raises:
     """
     command = 'show license features | grep License State'
     verify_string = 'ASAv Platform License State: Licensed'
     return verify_string_match(channel, command, verify_string)

def verify_asa_license_authorized(channel):
     """
     Purpose:    To verify smart license AUTHORIZED
     Parameters: ParamikoSSH class object, Default password, New Password
     Returns:    SUCCESS, None
     Raises:
     """
     command = 'show license features | grep enforce'
     verify_string = 'enforce mode: Authorized'
     return verify_string_match(channel, command, verify_string)

def get_asav_version(channel):
     """
     Purpose:  To get the ASAv version 
     Parameters: ParamikoSSH class object, Default password, New Password
     Returns: list [major version, minor version] 
     """

     try:
          command = "show version | grep Software Version"
          output = exec_command(channel, command)
          match = re.search(r'Version\s+([\d.()]+)', output)
          if not match:
               print("ERROR: Version not found")
               return None

          version_str = match.group(1)
          parts = version_str.split('.')
          if len(parts) < 2:
               print("ERROR: Invalid version format")
               return None

          major = parts[0]
          if major == '99':
               major = '9'
          minor = parts[1]

          major_match = re.match(r'\d+', major)
          minor_match = re.match(r'\d+', minor)
          if not major_match or not minor_match:
               print("ERROR: Invalid version format")
               return None

          return [int(major_match.group(0)), int(minor_match.group(0))]
     except IndexError as e:
          print("ERROR: Unable to get ASAv version: {}".format(repr(e)))
          return None
     except Exception as e:
          print("ERROR: Unable to get ASAv version: {}".format(repr(e)))
          return None

def register_smart_license(channel, smart_lic_token):
     """
     Purpose:    Register smart license
     Parameters: ParamikoSSH class object
     Returns:    SUCCESS, None
     Raises:
     """
     
     try:
          cmd1 = 'license smart deregister'
          cmd2 = 'license smart register idtoken '+smart_lic_token+' force'

          exec_command(channel,cmd1)
          time.sleep(2)
          exec_command(channel,cmd2)
          return 'SUCCESS'
     except Exception as e:
        raise Exception("ERROR: Registering smart license failed ",e)

def run_copy_file_running_config(channel, url, file_path):
     """
     Purpose:    To change configure running-config from HTTP/HTTPS
     Parameters: url, s3 bucket/any http server path
     Returns:    SUCCESS, None
     Raises:
     """
     try:
          cmd1 = 'copy /noconfirm ' + url + ' ' + file_path
          cmd2 = 'copy /noconfirm ' + file_path + ' running-config'
          write_memory_config = 'copy /noconfirm running-config startup-config'
          cmd3 = write_memory_config

          exec_command(channel,cmd1)
          exec_command(channel,cmd2)
          exec_command(channel,cmd3)

          print("Executing commands: " + cmd1)
          print("Executing commands: " + cmd2)
     except Exception as e:
          raise Exception("ERROR: Copying file failed ",e)

def verify_configuration_file_copy(channel, local_file_name):
     """
     Purpose:    To verify whether configuration file copied or not
     Parameters: ParamikoSSH class object, Default password, New Password
     Returns:    SUCCESS, None
     Raises:
     """
     command = 'show disk0: '
     verify_string = local_file_name
     return verify_string_match(channel, command, verify_string)