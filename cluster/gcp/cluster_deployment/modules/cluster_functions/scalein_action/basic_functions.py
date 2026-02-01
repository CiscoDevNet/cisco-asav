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
from google.cloud import secretmanager


def connect_ssh(ip, user, password, minutes):
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
                    #3 times because of old, new, reenter password
               #User admin logged in to ...
               if "User" in resp.decode("utf-8"):
                    return 'SUCCESS',channel,ssh
               time.sleep(10)
          except paramiko.AuthenticationException as exc:
               print("Exception occurred: AuthenticationException {}".format(repr(exc)))
               print(str(i),". Sleeping for 10 seconds")
               time.sleep(10)
          except paramiko.BadHostKeyException as exc:
               print("Exception(un-known) occurred: BadHostKeyException {}".format(repr(exc)))
               print(str(i),". Sleeping for 10 seconds")
               time.sleep(10)
          except paramiko.SSHException as exc:
               print("Exception(un-known) occurred: SSHException {}".format(repr(exc)))
               print(str(i),". Sleeping for 10 seconds")
               time.sleep(10)
          except BaseException as exc:
               #for timeout
               #print("Exception(un-known) occurred: BaseException {}".format(repr(exc)))
               print(str(i),". Sleeping for 10 seconds.BaseException")
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
     print("Going to EXEC Mode")
     cmd = "enable"
     exec_command(channel,cmd)
     msg = exec_command(channel,password)
     if "Repeat Password" in msg:
          exec_command(channel,password)
     return

    
def check_license_status(channel):
     print("Checking License Status")
     cmd = "show license status | include Status"
     msg = exec_command(channel,cmd)
     if "UNREGISTERED" in msg:
          return False    
     if "REGISTERED" in msg:
          print("License Found")
          return True
     #any other status
     return False

# "deregister"
def deregister_license(channel):
     if check_license_status(channel) == True:
          print("License Found")
          cmd = "license smart deregister"
          exec_command(channel,cmd)
          print("License Deregistered")
     else:
          print("No License Found, No need to Deregister")


# write memory
def save_config(channel):
     print("Saving the Configuration")
     cmd = "write memory"
     exec_command(channel,cmd)
     print("Configuration Saved")

def fetch_secret(project_id, secret_id, version_id):
     client = secretmanager.SecretManagerServiceClient()
     name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
     response = client.access_secret_version(request={"name": name})
     return response.payload.data.decode("UTF-8")

def disable_cluster(channel):
     print("Disabling Cluster")
     exec_command(channel,"conf t")
     cmd = "cluster group asav-cluster"
     exec_command(channel,cmd)
     cmd = "no enable"
     exec_command(channel,cmd)
     return