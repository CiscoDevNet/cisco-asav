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
Name:       basic_functions.py
Purpose:    This python file has basic functions for 
            SSH and running commands in ASAv.
"""
import paramiko
import time
import os
from google.cloud import secretmanager


def establishingConnection(ip, user, pKey, minutes):
     ssh = paramiko.SSHClient()
     ssh.load_system_host_keys()
     ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
     
     for i in range(6*minutes):
          try:
               ssh.connect(ip, username=user, pkey=pKey, timeout=10, disabled_algorithms=dict(pubkeys=["rsa-sha2-512", "rsa-sha2-256"]))
               channel = ssh.invoke_shell()
               resp = channel.recv(9999)
               print(resp.decode("utf-8"))
               if "User" in resp.decode("utf-8"):
                    return 'SUCCESS',channel,ssh
               time.sleep(10)
          except paramiko.AuthenticationException as exc:
               print("Exception occurred: AuthenticationException {}".format(repr(exc)))
               print(str(i)+". Sleeping for 10 seconds")
               time.sleep(10)
          except paramiko.BadHostKeyException as exc:
               print("Exception(un-known) occurred: BadHostKeyException {}".format(repr(exc)))
               print(str(i)+". Sleeping for 10 seconds")
               time.sleep(10)
          except paramiko.SSHException as exc:
               print("Exception(un-known) occurred: SSHException {}".format(repr(exc)))
               print(str(i)+". Sleeping for 10 seconds")
               time.sleep(10)
          except BaseException as exc:
               #for timeout
               #logging.info("Exception(un-known) occurred: BaseException {}".format(repr(exc)))
               print(str(i)+". Sleeping for 10 seconds.BaseException")
               time.sleep(10)

     print("Timeout after ", minutes, " minutes.")
     return

def responseMsg(channel):
     resp = channel.recv(9999) # 9999 is the number of bytes
     return resp.decode("utf-8")

def execCommand(channel,cmd):
     cmd = cmd + "\n"
     channel.send(cmd)
     time.sleep(3)  # 3 sec wait time
     resp = responseMsg(channel)
     print(resp)
     return resp
     
def closeShell(ssh):
     ssh.close()

# "enable"
def enableASA(channel, password):
     print("Going to EXEC Mode")
     cmd = "enable"
     execCommand(channel,cmd)
     msg = execCommand(channel,password)
     if "Repeat Password" in msg:
          execCommand(channel,password)
     return


# write memory
def saveConfig(channel):
     print("Saving the Configuration")
     cmd = "write memory"
     execCommand(channel,cmd)
     print("Configuration Saved")
     return

#change SSH Password
def changeSshPwd(channel,password):
     print("Changing SSH Password")
     cmd = "conf t"
     execCommand(channel,cmd)
     cmd = "username admin password "+password+" privilege 15"
     # do not use execCommand to avoid this on Logs
     cmd = cmd + "\n"
     channel.send(cmd)
     time.sleep(3)  # 3 sec wait time
     resp = responseMsg(channel)
     print("Password changed Successfully")

#change Hostname
def changeHostname(channel, name):
     print("Changing Hostname")
     cmd = "conf t"
     execCommand(channel,cmd)
     cmd = "hostname ciscoasav-"+ name
     execCommand(channel,cmd)
     print("Hostname changed Successfully")

def secretCode(project_id, secret_id, version_id):
     client = secretmanager.SecretManagerServiceClient()
     name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
     response = client.access_secret_version(request={"name": name})
     return response.payload.data.decode("UTF-8")
