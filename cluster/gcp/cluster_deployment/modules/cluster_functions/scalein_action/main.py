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
Name:       main.py
Purpose:    main function
PreRequisites: User has to create Secrets :"<resource-name-prefix>-enable-password", "<resource-name-prefix>-ssh-password"
"""
import base64
import json
from googleapiclient import discovery
import basic_functions as bf 
import os
import warnings
from cryptography.utils import CryptographyDeprecationWarning
with warnings.catch_warnings():
     warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)
     import paramiko
try:
     from StringIO import StringIO
except ImportError:
     from io import StringIO

def scale_in(data, context):
     """Triggered from a message on a Cloud Pub/Sub topic.
     Args:
          event (dict): Event payload.
          context (google.cloud.functions.Context): Metadata for the event.
     """
     try:
          data_buffer = base64.b64decode(data['data'])
     except Exception as e:
          print("ERROR: Exception occured in reading event data")
          return
     
     # Getting instance details
     log_entry = json.loads(data_buffer)
     resourceName = log_entry['protoPayload']['resourceName']
     pos = resourceName.find("instances/")
     instanceName = resourceName[pos+10:]
     project_id = log_entry['resource']['labels']['project_id']
     zone = log_entry['resource']['labels']['zone']
     api = discovery.build('compute', 'v1',cache_discovery=False)
     response = api.instances().get(project=project_id, zone=zone, instance=instanceName).execute()
     internal_ip = response['networkInterfaces'][1]['networkIP']
     
     # Accessing environment variables
     resource_name_prefix = os.getenv('RESOURCE_NAME_PREFIX')
     # These passwords are stored in secret manager
     asav_password         = os.getenv('ASAV_PASSWORD')
     asav_en_password      = os.getenv('ASAV_EN_PASSWORD')

     user = "admin"

     # Establishing SSH connection.
     try:
          status,channel,ssh = bf.connect_ssh(internal_ip, user, asav_password, 10)
     except Exception as e:
          print(f"ERROR: Exception occured in establishing SSH connection for instance {instanceName}, {e}")
          return
     
     # De-registering licensing
     try:
          bf.enable_asa(channel, asav_en_password)
          bf.deregister_license(channel)
          bf.save_config(channel)
          bf.disable_cluster(channel)
          print("All scale-in operations completed successfully")
     except Exception as e:
          print(f"ERROR: {e}")
     finally:
          bf.close_shell(ssh)