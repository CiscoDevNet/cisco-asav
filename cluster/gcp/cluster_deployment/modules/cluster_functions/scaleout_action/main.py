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
PreRequisites: User has to create Secrets :<resource_name_prefix>-enable-password, <resource_name_prefix>-ssh-password
"""
import base64
import json
import time
from googleapiclient import discovery
import basic_functions as bf
import cluster_functions as cf
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
from google.cloud import functions_v1

timeout_time = 480 # Safe Function timeout(seconds) to recall.

def is_time_up(start_time):
    return time.time() - start_time > timeout_time

def recalling(data, project_id, region, function_name):
    try:
        # Create client and function path
        client      = functions_v1.CloudFunctionsServiceClient()
        function    = client.cloud_function_path(project_id, region, function_name)
    
        # Creating payload
        payload = {
                "data": base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')
            }
        # Creating request
        request = functions_v1.CallFunctionRequest(
            name=function,
            data=str(payload),
        )
    except Exception as e:
        print("ERROR: Exception occured in creating recall request ",e)

    # Call the function but do not wait for response,
    # this will raise DeadlineExceeded exception, ignore it.
    try:
        response = client.call_function(request=request, timeout=5)
        print(f"INFO: Function has been recalled successfully, DATA:{data}")
    except Exception as e:
        if e.__class__.__name__ != 'DeadlineExceeded':
            print("ERROR: Exception occured in recalling ",e)
    return


def scale_out(event, context):
    """
    Triggered from a message on a Cloud Pub/Sub topic.
    Args:
        event (dict): Event payload.
        context (google.cloud.functions.Context): Metadata for the event.
    """
    start_time = time.time()
    try:
        data_buffer = base64.b64decode(event['data'])
        data        = json.loads(data_buffer)
        print(data)
    except Exception as e:
        print("ERROR: Exception occured in reading event data")
        return
    
    # ADDING COUNTER TO TRACK RECALLING
    max_retry = 5
    if not ("counter" in data):
        data["counter"] = 1
        current_counter = 1
        data["first_boot_config_done"] = False
    else:
        try:
            current_counter = int(data["counter"]) + 1
            data["counter"] = current_counter
        except Exception as e:
            print("ERROR: Exception occured in getting current recall counter")
            return
        
    # Accessing environment variables
    try:
        resource_name_prefix   = os.getenv('RESOURCE_NAME_PREFIX')
        license_token          = os.getenv('LICENSE_TOKEN')
        # These passwords are stored in secret manager
        asav_password         = os.getenv('ASAV_PASSWORD')
        asav_en_password      = os.getenv('ASAV_EN_PASSWORD')
    except Exception as e:
        print("ERROR: Exception occurred in accessing environment variables", e)
        return

    # Getting instance details
    try:
        resourceName   = data['protoPayload']['resourceName']
        pos            = resourceName.find("instances/")
        instanceName   = resourceName[pos+10:] #strlen(instances) = 10
        project_id     = data['resource']['labels']['project_id']
        zone           = data['resource']['labels']['zone']
        region          = zone.rsplit("-", 1)[0]
        function_name   = resource_name_prefix + "-asav-scaleout-action"

        print(f"INFO: {instanceName} Function call - {current_counter}")
    except KeyError as e:
        print("ERROR: Key not found in event data", e)
        return
    except Exception as e:
        print("ERROR: Exception occurred in getting instance details", e)
        return
    
    if current_counter > max_retry:
        print(f"ERROR: MAX RETRY TO CONFIGURE INSTANCE {instanceName} HAS REACHED, SCALEOUT FAILED")
        return
    
    # Fetching instance management IP
    try:
        api         = discovery.build('compute', 'v1', cache_discovery=False)
        response    = api.instances().get(project=project_id, zone=zone, instance=instanceName).execute()
        internal_ip = response['networkInterfaces'][1]['networkIP']
        print(f"INFO: Management IP of {instanceName} is {internal_ip}")
    except Exception as e:
        print(f"ERROR: Exception occurred in fetching instance details, {e}")
        recalling(data, project_id, region, function_name)
        return "Recalling"

    # Read config file
    try:
        current_dir = os.path.dirname(__file__)  # Get the directory of the current script (main.py)
        # File name "configuration.txt" should be present to apply any custom config. 
        file_path   = os.path.join(current_dir, 'configuration.txt')
        lines = []
        with open(file_path, 'r') as file:
            for line in file:
                if not line.startswith('!'):
                    lines.append(line.strip())
    except Exception as e:
        print("WARN: configuration file not provided/found", e)
    
    # Establishing SSH connection.
    user           = "admin"
    def_password   = "AsAv_ClU3TeR44"   # Default password only for first time login
    
    # First boot tasks
    if not data["first_boot_config_done"]:
        try:
            print("INFO: Waiting for first boot to complete")
            time.sleep(120)
            
            # SSH using default password if its first boot.
            try:
                status,channel,ssh = bf.connect_ssh(internal_ip, user, def_password, 3)
            except Exception as e:
                print(f"ERROR: Exception occured in establishing SSH connection for instance {instanceName}, {e}")
                return
            
            # Update enable, SSH passwords and hostname
            bf.enable_asa(channel, asav_en_password)
            bf.change_ssh_pwd(channel, user, asav_password)
            bf.change_hostname(channel)
            bf.save_config(channel)
        except Exception as e:
            print("ERROR: Exception occured in first boot tasks", str(e))
            recalling(data, project_id, region, function_name)
            return "Recalling"

        data["enabled_cluster"] = False
        data["joined_cluster"]  = False
        data["custom_config"]   = False
        data["licensed"]        = False
        data["full_cluster"]    = False
        data["password_updated"]= True
        data["first_boot_config_done"] = True
    else:   
        try:
            status,channel,ssh = bf.connect_ssh(internal_ip, user, asav_password, 5)
            bf.enable_asa(channel, asav_en_password)
        except Exception as e:
            print(f"ERROR: Exception establishing SSH connection after enabling clustering for instance {instanceName}, {e}")
            recalling(data, project_id, region, function_name)
            return "Recalling"
        
    # Apply cluster config and enable cluster
    try:
        if not data["enabled_cluster"]:
            cf.configure_cluster(channel, internal_ip)
            data["enabled_cluster"] = True
            
            bf.close_shell(ssh)
            # Wait for node to finsh cluster bootstap tasks and join cluster.
            time.sleep(30)
            
            # Create a new SSH connection.
            try:
                status,channel,ssh = bf.connect_ssh(internal_ip, user, asav_password, 5)
                bf.enable_asa(channel, asav_en_password)
            except Exception as e:
                print(f"ERROR: Exception establishing SSH connection after enabling clustering for instance {instanceName}, {e}")
                recalling(data, project_id, region, function_name)
                return "Recalling"
    except Exception as e:
        print("ERROR: Exception occured in applying cluster config", e)
        recalling(data, project_id, region, function_name)
        return "Recalling"

    # Verifying if node joined the cluster
    while (time.time() - start_time) < timeout_time and not data["joined_cluster"]:
        try:
            node_state = cf.node_state(channel)
            if node_state in ["DATA_NODE", "CONTROL_NODE"]:
                print(f"INFO: Instance {instanceName} has joined cluster as {node_state}")
                data["joined_cluster"] = True
            elif node_state != "NOT_JOINED":
                print(f"INFO: Instance {instanceName} has not joined cluster, is in {node_state} state")
            else:
                print(f"INFO: Instance {instanceName} has not joined cluster")
            time.sleep(20)
        except Exception as e:
            print("ERROR: Exception occurred in checking node's cluster status", e)

    if is_time_up(start_time):
        if not data["joined_cluster"]:
            print("DEBUG: Node did not join cluster, recalling")
        bf.close_shell(ssh)
        recalling(data, project_id, region, function_name)
        return "Recalling"

    # Applying extra config from configuration.txt
    if not data["custom_config"]:
        try:
            node_state = cf.node_state(channel)
            # Only perform if it's a Control node
            if node_state == "CONTROL_NODE":   
                cf.apply_config_file(channel, lines)
                data["custom_config"] = True
            else:
                data["custom_config"] = True
        except Exception as e:
            print(f"ERROR: Exception occured in applying custom configuration, {e}")

    if is_time_up(start_time):
        bf.close_shell(ssh)
        recalling(data, project_id, region, function_name)
        return "Recalling"

    min_instance_count = 0 # Initialization
    try:
        # Fetching minimum instance count of Instance Group
        instance_group_name       = resource_name_prefix+"-asav-instance-group"
        instance_group_response   = api.regionInstanceGroupManagers().get(project=project_id,region="-".join(zone.split("-")[:2]),instanceGroupManager=instance_group_name).execute()
        min_instance_count        = instance_group_response['targetSize']
        print(f"INFO: Current instance count of instance group {instance_group_name} is {min_instance_count}")
    except Exception as e:
        print("ERROR: Exception occured in getting current size of the instance group")
    
    try:
        if license_token not in [None, "", "None"]:
            # Applying License configuration.
            while (time.time() - start_time) < timeout_time and not data["licensed"]:
                try:
                    if cf.execute_cluster_license(channel, 'BYOL', license_token) != 'SUCCESS':
                        print(f"WARN: Could not verify license {instanceName}, will retry")
                    else:
                        data["licensed"] = True
                        print(f"License has been applied successfully to {instanceName}")
                    time.sleep(20)
                except Exception as e:
                    print(f"ERROR: Exception occurred in licensing {instanceName}, {e}")

            if not data["licensed"]:
                print(f"WARN: License could not be verified, recalling")
                bf.close_shell(ssh)
                recalling(data, project_id, region, function_name)
                return "Recalling"
        else:
            print("WARN: License token not provided, skipping license configuration")
            
        # Verify full cluster formation
        while (time.time() - start_time) < timeout_time and not data["full_cluster"]:
            try:
                if cf.verify_cluster_status(channel, min_instance_count) == 'SUCCESS':
                    data["full_cluster"] = True
                    print(f"INFO: All nodes joined cluster successfully")
                else:
                    print(f"WARN: All nodes have not joined cluster, waiting for full cluster formation")
                    time.sleep(10)
            except Exception as e:
                print("ERROR: Exception occured in verifying full cluster formation",e)
            time.sleep(20)
                
        if not data["full_cluster"]:
            print(f"WARN: Full cluster formation could not be verified, recalling")
            bf.close_shell(ssh)
            recalling(data, project_id, region, function_name)
            return "Recalling"

        print("INFO: Scaleout Action completed successfully")
    except Exception as e:
        print("ERROR: Exception occured",e)
        recalling(data, project_id, region, function_name)
    finally:
        # Closing connection
        bf.close_shell(ssh)
        return