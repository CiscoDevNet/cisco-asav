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
Name:       cluster_functions.py
Purpose:    This python file has functions for configuring clustering on the new scaled-out instances
"""
import time
import basic_functions as bf
import re

def configure_cluster(channel, internal_ip):
    """
    Configure cluster on ASAv.

    Args:
        channel (param_type): SSH channel
        internal_ip (param_type): Internal IP of the ASAv instance
    """
    try:
        asav_version = bf.get_asav_version(channel)
        print(asav_version)

        octet_str = internal_ip.split('.')[3]
        octet = int(octet_str)  # for math

        local_unit = f"local-unit {octet_str}"

        # Proper version compare: >= 9.24
        if tuple(asav_version[:2]) >= (9, 24):
            cluster_octet = octet + 192
            if not (0 <= cluster_octet <= 255):
                raise ValueError(f"Computed cluster IP octet out of range: {cluster_octet}")

            cls_int = f"cluster-interface vni1 ip 169.254.200.{cluster_octet} 255.255.255.0"
        else:
            cls_int = f"cluster-interface vni1 ip 1.1.1.{octet_str} 255.255.255.0"

        print(cls_int)

        write_memory_config = "copy /noconfirm running-config startup-config"

        cmds = [
            "cluster group asav-cluster",
            local_unit,
            cls_int,
            "priority 1",
            "enable noconfirm",
            write_memory_config,
        ]

        for cmd in cmds:
            bf.exec_command(channel, cmd)

        print("INFO: Cluster configuration applied successfully")
    except Exception as e:
        raise Exception("ERROR: Cluster config failed", e)

def node_state(channel):
    """
    Purpose:    Fetch cluster node state
    Parameters: SSH channel
    Returns:    NOT_JOINED, DATA_NODE, CONTROL_NODE
    Raises:
    """
    node_state = "NOT_JOINED"
    cmd = "show cluster info | grep NODE"
    try:
        msg   = bf.exec_command(channel, cmd)
        match = re.search(r'This is .*state (\w+)', msg)
        if match:
            node_state = match.group(1)
        return node_state
    except Exception as e:
        raise Exception ("ERROR: Exception occurred in checking cluster node status",e)

def verify_cluster_status(channel, desired_size):
    """
    Purpose:    Verify cluster formation status
    Parameters: Object of AutoscaleGroup and ASAvInstance class
    Returns:    SUCCESS, FAIL
    Raises:
    """
    
    print("Expected Cluster Size: {}".format(desired_size))
    try:
        if desired_size != 1:
            status = bf.fetch_cluster_status(channel)
            control = status.count('CONTROL_NODE')
            members = status.count('DATA_NODE')
            print("Control node found: {}".format(control))
            print("Data nodes found: {}".format(members))
            if control == 1 and members == (desired_size - 1):
                print('Cluster formed correctly with expected numbers of nodes')
                return 'SUCCESS'
            else:
                print('Waiting for cluster to be formed ..')
                return 'FAIL'
        else:
            status = bf.fetch_cluster_status(channel)
            if "CONTROL_NODE" in status:
                print('Cluster formed correctly with expected numbers of nodes')
                return "SUCCESS"
            else:
                print('Waiting for cluster to be formed..')
                return 'FAIL'
    except Exception as e:
        raise Exception("Exception occurred {}".format(e))

def apply_config_file(channel, ConfigFileContent):
    """
    Purpose:    This applies contents of config file to the device
    Parameters: List containing the commands in Configuration.txt
    Returns:    SUCCESS, FAIL
    Raises:
    """
    # Apply device configuration
    if ConfigFileContent:
        try:
            for cmd in ConfigFileContent:
               bf.exec_command(channel,cmd)
        except Exception as e:
            raise Exception("ERROR: Applying config failed ",e) 
    else:
        print("INFO: The config file is empty")    

def execute_cluster_license(channel, ASA_LICENSE_TYPE, smart_lic_token):
    """
    Purpose:    This configures Licensing of ASAv instance
    Parameters: Object of ASAvInstance class
    Returns:    SUCCESS, FAIL
    Raises:
    """
    # Apply license configuration
    try:
        if ASA_LICENSE_TYPE == 'BYOL':
            print("Found BYOL Licensing type in User Input")
            print("Verifying License status inside the device")
            if bf.verify_asa_smart_licensing_enabled(channel) == 'SUCCESS':
                print('ASA is smart-license enabled')
                if bf.verify_asav_byol_licensed(channel) == 'SUCCESS' and bf.verify_asa_license_authorized(channel) == 'SUCCESS':
                    print("ASAv is already Licensed")
                    return 'SUCCESS'
                elif bf.register_smart_license(channel, smart_lic_token) == 'SUCCESS':
                    print('Registering license...')
                    time.sleep(30)
                    if bf.verify_asav_byol_licensed(channel) == 'SUCCESS' and bf.verify_asa_license_authorized(channel) == 'SUCCESS':
                        print('ASAv Licensed Successfully!!')
                        return 'SUCCESS'
            return 'FAIL'     
        else:
            print("Invalid user input for ASAv License Type")
            return 'FAIL'
    except Exception as e:
        raise Exception("ERROR: Exception occurred while applying license configuration ", e)