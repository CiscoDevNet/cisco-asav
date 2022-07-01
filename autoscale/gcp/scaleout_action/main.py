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
Name:       main.py
Purpose:    main function
PreRequisites: User has to create "asav-private-key",
               "asav-en-password", "asav-new-password"
"""
import base64
import json
from googleapiclient import discovery
import basic_functions as bf 
import os
import paramiko
try:
     from StringIO import StringIO
except ImportError:
    from io import StringIO

def change_pass(data, context):
     """Triggered from a message on a Cloud Pub/Sub topic.
     Args:
          event (dict): Event payload.
          context (google.cloud.functions.Context): Metadata for the event.
     """
     
     data_buffer = base64.b64decode(data['data'])
     log_entry = json.loads(data_buffer)

     # To get the Instance Name
     resourceName = log_entry['protoPayload']['resourceName']
     pos = resourceName.find("instances/")
     instanceName = resourceName[pos+10:] #strlen(instances) = 10
     instance_suffix = instanceName[-4:] #last 4 characters of instance name
     project_id = log_entry['resource']['labels']['project_id']
     zone = log_entry['resource']['labels']['zone']
     api = discovery.build('compute', 'v1',cache_discovery=False)
     response = api.instances().get(project=project_id, zone=zone, instance=instanceName).execute()
     internal_ip = response['networkInterfaces'][2]['networkIP']
     print(internal_ip)

     user = "admin"
     
     secret_id = "asav-private-key"
     version_id = "1"
     pKey = bf.secretCode(project_id, secret_id, version_id)
     pKey = StringIO(pKey)
     pKey = paramiko.RSAKey.from_private_key(pKey)
  
     status,channel,ssh = bf.establishingConnection(internal_ip, user, pKey, 10)

     secret_id = "asav-new-password"
     version_id = "1"
     new_password = bf.secretCode(project_id, secret_id, version_id)

     secret_id = "asav-en-password"
     version_id = "1"
     en_password = bf.secretCode(project_id, secret_id, version_id)
     
     bf.enableASA(channel, en_password)
     bf.changeSshPwd(channel,new_password)
     bf.changeHostname(channel, instance_suffix)
     bf.saveConfig(channel)
     
     bf.closeShell(ssh)
