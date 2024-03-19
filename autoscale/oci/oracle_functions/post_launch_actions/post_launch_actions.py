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

Name:       post_launch_actions.py
Purpose:    This python file has ASAv related class & methods
            Classes in this python files are being used for
            performing Post-Launch action in OCI ASAv Autoscale.
"""

import io
import json
import logging
import oci
import time
import socket
import base64

from fdk import response

logger = logging.getLogger()

class PostLaunchAction:
    def __init__(self, compartmentId, instanceId):
        self.signer = oci.auth.signers.get_resource_principals_signer()
        self.computeClient = oci.core.ComputeClient(config={}, signer=self.signer)
        self.virtualNetworkClient = oci.core.VirtualNetworkClient(config={}, signer=self.signer)
        self.computeManagementClient = oci.core.ComputeManagementClient(config={}, signer=self.signer)
        self.loadBalancerClient = oci.load_balancer.LoadBalancerClient(config={}, signer=self.signer)
        self.ons_client = oci.ons.NotificationDataPlaneClient(config={}, signer=self.signer)
        self.compartmentId = compartmentId
        self.instanceId = instanceId
        self.retries = 3
        self.identifier = ''

    def get_all_instances_id_in_pool(self, instancePoolId):
        """
        Purpose:   To get OCID of all Instances in the Instance Pool
        Parameters: Compartment OCID, Instance Pool OCID
        Returns:    List(Instance OCID)
        Raises:
        """
        for i in range(0, self.retries):
            try:
                all_instances_in_instance_pool = self.computeManagementClient.list_instance_pool_instances(
                                            compartment_id = self.compartmentId,
                                            instance_pool_id = instancePoolId).data

                all_instances_id = [instance.id for instance in all_instances_in_instance_pool]
                return all_instances_id

            except Exception as e:
                logger.error(f"POST LAUNCH ACTION {self.identifier}: ERROR IN GETTING INSTANCE LIST FROM INSTANCE POOL, RETRY COUNT:{str(i+1)}, REASON:{repr(e)}")
                continue

        return None

    def terminate_instance(self):
        """
        Purpose:   To Terminate any Instance in the Instance Pool (Not Scale-In)
        Parameters: Instance OCID to delete.
        Returns:    Boolean
        Raises:
        """
        for i in range(0, self.retries):
            try:
                terminate_instance_response = self.computeClient.terminate_instance(
                instance_id = self.instanceId,
                preserve_boot_volume=False)

                logger.info(f"POST LAUNCH ACTION {self.identifier}: INSTANCE TERMINATED AS SOMETHING WENT WRONG, PLEASE CHECK PREVIOUS LOGS")
                return True

            except Exception as e:
                logger.info(f"POST LAUNCH ACTION {self.identifier}: ERROR OCCURRED WHILE TERMINATING INSTANCE, RETRY COUNT:{str(i+1)}, REASON:{repr(e)}")
                continue
        return False

    def get_management_public_ip(self):
        """
        Purpose:    To get Management interface (vnic) public IP.
        Parameters: Compartment OCID, Instance OCID.
        Returns:    Dict     Example: {'management_public_ip': '54.88.96.211'}
        Raises:
        """
        for i in range(0, self.retries):
            try:
                vnic_attachments = oci.pagination.list_call_get_all_results(
                self.computeClient.list_vnic_attachments,
                compartment_id = self.compartmentId,
                instance_id = self.instanceId,
                ).data

                vnics = [self.virtualNetworkClient.get_vnic(va.vnic_id).data for va in vnic_attachments]

                for vnic in vnics:
                    if vnic.is_primary:
                        ip_response = vnic.public_ip
                        return ip_response

            except Exception as e:
                logger.error(f"POST LAUNCH ACTION {self.identifier}: ERROR IN RETRIEVING MANAGEMENT PUBLIC IP, RETRY COUNT: {str(i)}, ERROR: {repr(e)}")
                continue

        return None

    def attach_interface(self, interfaceName, subnetId, nsgIdList):
        """
        Purpose:   To create Non-primary interface (vnic) in a Instance.
        Parameters: Instance OCID, Interface Name, Subnet OCID
        Returns:    A Response object with data of type VnicAttachment
        Raises:
        """
        for i in range(1, self.retries+1):
            try:
                computeCompositeClient = oci.core.ComputeClientCompositeOperations(client=self.computeClient)

                attach_vnic_details=oci.core.models.AttachVnicDetails(
                create_vnic_details=oci.core.models.CreateVnicDetails(
                    assign_public_ip = False,
                    skip_source_dest_check = True,
                    subnet_id = subnetId,
                    nsg_ids = nsgIdList),
                    instance_id = self.instanceId,
                    display_name = interfaceName)

                attach_vnic_response = computeCompositeClient.attach_vnic_and_wait_for_state(attach_vnic_details, wait_for_states=["ATTACHED", "UNKNOWN_ENUM_VALUE"]).data
                vnicId = attach_vnic_response.vnic_id

            except Exception as e:
                logger.error(f"POST LAUNCH ACTION {self.identifier}: RETRY: {i} ERROR IN ATTACHING {interfaceName} VNIC, ERROR {e}")
                time.sleep(10)
                continue
            """
            NOTE: Code following below for this function has been written to update VNIC name after attachment
            because it is not taking given display name at them time of attachment itself.
            If the issue gets resolved in future this code should be removed.
            """
            try:
                virtualNetworkCompositeClient = oci.core.VirtualNetworkClientCompositeOperations(client = self.virtualNetworkClient)
                update_vnic_details=oci.core.models.UpdateVnicDetails(display_name = interfaceName)
                update_vnic_response = virtualNetworkCompositeClient.update_vnic_and_wait_for_state(vnicId, update_vnic_details, wait_for_states=["AVAILABLE", "UNKNOWN_ENUM_VALUE"]).data
                return update_vnic_response

            except Exception as e:
                logger.error(f"POST LAUNCH ACTION {self.identifier}:  RETRY: {i} ERROR IN UPDATING {interfaceName} VNIC, ERROR {e}")
        return None

    def add_to_backend_set(self, loadBalancerId, backendSetName, ipAddr, portNo):
        """
        Purpose:   To add instacne as backend server to the backend set of the load balancer
        Parameters: Ip Address of instance, Port Number, Backend set name, Load Balancer OCID
        Returns:    Str
        Raises:
        """
        for i in range(0, self.retries):
            try:
                create_backend_response = self.loadBalancerClient.create_backend(
                    create_backend_details = oci.load_balancer.models.CreateBackendDetails(
                                                ip_address = ipAddr,
                                                port = portNo,
                                                #weight=,
                                                #backup=True,
                                                #drain=False,
                                                #offline=False
                                            ),
                        load_balancer_id = loadBalancerId,
                        backend_set_name = backendSetName
                        ).data
                return "Successful"

            except Exception as e:
                logger.error(f"POST LAUNCH ACTION {self.identifier}: ERROR IN ADDING TO BACKEND SET, RETRY COUNT: {str(i+1)}, ERROR: {repr(e)}, RESPONSE: {repr(create_backend_response)}")
                continue

        return "Failed"

    def get_netmask_from_subnet_cidr(self, subnetId):
        """
        Purpose:   To calculate Netmask of Subnet.
        Parameters: Subnet OCID
        Returns:    Str
        Raises:
        """
        try:
            subnet_cidr = (self.virtualNetworkClient.get_subnet(subnet_id = subnetId).data).cidr_block
            (addrString, cidrString) = subnet_cidr.split('/')
            cidr = int(cidrString)

            mask = [0, 0, 0, 0]
            for i in range(cidr):
                mask[int(i/8)] = mask[int(i/8)] + (1 << (7 - i % 8))

            netmask = ".".join(map(str, mask))
            return netmask
        except Exception as e:
            logger.error(f"POST LAUNCH ACTION {self.identifier}: ERROR IN CALCULATING NETMASK{repr(e)}")
            return None

    def decrypt_cipher(self, cipherText, cryptEndpoint, keyId):
        """
        Purpose:   To decrypt encrypted password.
        Parameters: Encrypted Password, Cryptographic Endpoint, Master Key OCID
        Returns:    password in plaintext (str)
        Raises:
        """
        for i in range(0, self.retries):
            try:
                key_management_client = oci.key_management.KmsCryptoClient(config={}, signer = self.signer, service_endpoint = cryptEndpoint)

                decrypt_response = key_management_client.decrypt(
                    decrypt_data_details=oci.key_management.models.DecryptDataDetails(
                        ciphertext = cipherText,
                        key_id = keyId)).data

                return base64.b64decode(decrypt_response.plaintext).decode('utf-8')

            except Exception as e:
                logger.error(f"POST LAUNCH ACTION {self.identifier}: ERROR IN DECRYPTING PASSWORD ERROR: {e}")
                continue

        return None

    def publish_message(self, topicId, msg):
        """
        Purpose:   To publish message to OCI Notification.
        Parameters: Topic ID, Message
        Returns:    Bool
        Raises:
        """
        for i in range(0, self.retries):
            try:
                publish_message_response = self.ons_client.publish_message(
                    topic_id = topicId,
                    message_details=oci.ons.models.MessageDetails(
                        body = json.dumps(msg),
                        title = "Configure_ASAv_Recall")).data

                return True
            except Exception as e:
                logger.info(f"POST LAUNCH ACTION {self.identifier}: ERROR IN CALLING CONFIGURE ASAv {repr(e)}")
                continue
        return False
    
def handler(ctx, data: io.BytesIO=None):
    """
        Purpose:   Main Function, receive JSON payload, Environmental Variable, implementation logic.
        Parameters: ctx (Contains Environmental Variables passed), data (Json Payload emit by event which called this function)
        Returns:    Response
        Raises:
    """
    # GET FUNCTION PAYLOAD
    try:
        body = json.loads(data.getvalue())
        data = body.get("data")
        instanceId = data.get("resourceId")
        compartmentId = data.get("compartmentId")
        begin_time = int(time.time())
        identifier = str(instanceId[-5:])
        logger.info(f"{identifier} ----POST LAUNCH ACTION CALLED----")
    except Exception as ex:
        logger.error(f"POST LAUNCH ACTION: ERROR IN PARSING JSON PAYLOAD, PLEASE MANUALLY DELETE THE INSTANCE FOR WHICH IT FAILED: {repr(ex)}")
        return f"POST LAUNCH ACTION: ERROR IN PARSING JSON PAYLOAD, {repr(ex)}"

    #GET ENVIRONMENT VARIABLES
    try:
        environmentVariables = ctx.Config()
        outsideInterfaceName = environmentVariables["outside_interface_name"]
        outsideSubnetId = environmentVariables["outside_subnet_id"]
        ELB_Id = environmentVariables["elb_id"]
        ELB_BackendSetName = environmentVariables["elb_backend_set_name"]
        ELB_ListenerPortNumber = (environmentVariables["elb_listener_port_no"])
        instancePoolId = environmentVariables["instance_pool_id"]
        insideInterfaceName = environmentVariables["inside_interface_name"]
        insideSubnetId = environmentVariables["inside_subnet_id"]
        ILB_Id = environmentVariables["ilb_id"]
        ILB_BackendSetName = environmentVariables["ilb_backend_set_name"]
        ILB_ListenerPortNumber = (environmentVariables["ilb_listener_port_no"])
        configuration_file_url = environmentVariables["configuration_file_url"]
        outsideNSGId = environmentVariables["outside_nsg_id"]
        insideNSGId = environmentVariables["inside_nsg_id"]
        asavEncryptedPassword = environmentVariables["encrypted_password"]
        cryptEndpoint = environmentVariables["cryptographic_endpoint"]
        master_key_id = environmentVariables["master_key_id"]
        configure_asav_topic_id = environmentVariables["configure_asav_topic_id"]
        log_level = environmentVariables["log_level"] # Set to DEBUG in function environment variabled for detailed logs.
    except Exception as e:
        logger.error(f"POST LAUNCH ACTION {identifier}: ERROR IN RETRIEVING ENVIRONMENT VARIABLES {repr(e)}")
        return f"POST LAUNCH ACTION {identifier}: FAILED WITH THIS INSTANCE"

    # SETING LOG LEVEL
    try:
        if log_level == "DEBUG":
            logging.basicConfig(force=True, level="DEBUG")
        else:
            logging.basicConfig(force=True, level="INFO")
    except Exception as e:
        logger.error(f"POST LAUNCH ACTION {identifier}: ERROR IN SETTING LOG LEVEL")
        logging.basicConfig(force=True, level="INFO")
    
    # CREATING POST LAUNCH ACTION CLASS OBJECT
    postLaunchActionObject = PostLaunchAction(compartmentId, instanceId)
    postLaunchActionObject.identifier = identifier

    # CHECK IF INSTANCE IS PART OF AUTOSCALE INSTANCE POOL
    all_instances_id = postLaunchActionObject.get_all_instances_id_in_pool(instancePoolId)
    logger.debug(f"POST LAUNCH ACTION {identifier}: All instances id in the pool : {all_instances_id}")
    if all_instances_id == None:
        return

    if instanceId in all_instances_id:
        try:
            time.sleep(25) # To give enough time for management vnic to come up properly.
            #______________________________________________________________________________________________________________________
            # ATTACHING INSIDE VNIC
            attach_inside_interface_response = postLaunchActionObject.attach_interface(insideInterfaceName, insideSubnetId, [insideNSGId])
            logger.debug(f"POST LAUNCH ACTION {identifier}: Attach inside interface response {attach_inside_interface_response}")
            if attach_inside_interface_response != None:
                logger.info(f"POST LAUNCH ACTION {identifier}: Inside VNIC attached successfully")
                insideInterfaceIpAddress = attach_inside_interface_response.private_ip
            else:
                logger.error(f"POST LAUNCH ACTION {identifier}: INSIDE VNICE ATTACHMENT FAILED, INSTACE WILL BE TERMINATED")
                terimate_instance_response = postLaunchActionObject.terminate_instance()
                return f"POST LAUNCH ACTION {identifier}: FAILED WITH THIS INSTANCE"
            time.sleep(5)
            #______________________________________________________________________________________________________________________
            # ATTACHING OUTSIDE VNIC
            attach_outside_interface_response = postLaunchActionObject.attach_interface(outsideInterfaceName, outsideSubnetId, [outsideNSGId])
            logger.debug(f"POST LAUNCH ACTION {identifier}: Attach outside interface response {attach_outside_interface_response}")
            if attach_outside_interface_response != None:
                logger.info(f"POST LAUNCH ACTION {identifier}: Outside VNIC attached successfully")
                outsideInterfaceIpAddress = attach_outside_interface_response.private_ip
            else:
                logger.error(f"POST LAUNCH ACTION {identifier}: OUTSIDE VNIC ATTACHMENT FAILED, INSTACE WILL BE TERMINATED")
                terimate_instance_response = postLaunchActionObject.terminate_instance()
                return f"POST LAUNCH ACTION {identifier}: FAILED WITH THIS INSTANCE"
            time.sleep(5)
            #______________________________________________________________________________________________________________________
        except Exception as e:
            logger.error(f"POST LAUNCH ACTION {identifier}: EXCEPTION OCCURED WHILE ATTACHING THE INTERFACES, INSTACE WILL BE TERMINATED   {repr(e)}")
            terimate_instance_response = postLaunchActionObject.terminate_instance()
            return f"POST LAUNCH ACTION {identifier}: FAILED WITH THIS INSTANCE"
        #__________________________________________________________________________________________________________________________
        # ADDING TO INTERNAL LOAD BALANCER
        # Note: ILB_ListenerPortNumber is passed in the form of string so we need to create list out of it.
        ilb_listener_port_list = list(map(lambda x: int(x.strip()), ILB_ListenerPortNumber.split(',')))
        try:
            for iPort in ilb_listener_port_list:
                add_to_ILB_backend_set_response = postLaunchActionObject.add_to_backend_set(ILB_Id, ILB_BackendSetName, insideInterfaceIpAddress, iPort)
                logger.debug(f"POST LAUNCH ACTION {identifier}: add_to_ILB_backend_set_response {add_to_ILB_backend_set_response}")
                time.sleep(5)
                logger.info(f"POST LAUNCH ACTION {identifier}: Add to Internal Backend Set response for listener port {iPort} is {repr(add_to_ILB_backend_set_response)}")
        except Exception as e:
            logger.error(f"POST LAUNCH ACTION {identifier}: ADD TO INTERNAL BACKEND SET ACTION GOT FAILED INSTACE WILL BE TERMINATED  {repr(e)}")
            terimate_instance_response = postLaunchActionObject.terminate_instance()
            return f"POST LAUNCH ACTION {identifier}: FAILED WITH THIS INSTANCE"
        #__________________________________________________________________________________________________________________________
        # ADDING TO EXTERNAL LOAD BALANCER
        # Note: ELB_ListenerPortNumber is passed in the form of string so we need to create list out of it.
        elb_listener_port_list = list(map(lambda x: int(x.strip()), ELB_ListenerPortNumber.split(',')))
        try:
            for ePort in elb_listener_port_list:
                add_to_ELB_backend_set_response = postLaunchActionObject.add_to_backend_set(ELB_Id, ELB_BackendSetName, outsideInterfaceIpAddress, ePort)
                logger.debug(f"POST LAUNCH ACTION {identifier}: add_to_ELB_backend_set_response {add_to_ELB_backend_set_response}")
                time.sleep(5)
                logger.info(f"POST LAUNCH ACTION {identifier}: Add to external backend set response for listener port {ePort} is {repr(add_to_ELB_backend_set_response)}")
        except Exception as e:
            logger.error(f"POST LAUNCH ACTION {identifier}: ADD TO EXTERNAL BACKEND SET ACTION GOT FAILED INSTACE WILL BE TERMINATED  {repr(e)}")
            terimate_instance_response = postLaunchActionObject.terminate_instance()
            return f"POST LAUNCH ACTION {identifier}: FAILED WITH THIS INSTANCE"
        #__________________________________________________________________________________________________________________________
        # CREATING PAYLOAD FOR CONFIGURE ASAv FUNCTION
        configure_asav_payload = {}
        configure_asav_payload["counter"] = 1
        configure_asav_payload["instance_id"] = instanceId
        configure_asav_payload["inside_interface_ip"] = insideInterfaceIpAddress
        configure_asav_payload["outside_interface_ip"] = outsideInterfaceIpAddress
        configure_asav_payload["inside_subnet_netmask"] = postLaunchActionObject.get_netmask_from_subnet_cidr(insideSubnetId)
        configure_asav_payload["outside_subnet_netmask"] = postLaunchActionObject.get_netmask_from_subnet_cidr(outsideSubnetId)
        configure_asav_payload["management_public_ip"] = postLaunchActionObject.get_management_public_ip()
        logger.debug(f"POST LAUNCH ACTION {identifier}: configure_asav_payload {configure_asav_payload}")
        #__________________________________________________________________________________________________________________________
        # WILL WAIT SOME TIME SO THAT ASAv FINISH UP FIRST TIMEBOOT
        post_launch_time = time.time()
        time_elapsed = round(post_launch_time - begin_time,2)
        logger.info(f"POST LAUNCH ACTION {identifier}: WAITING FOR ASAv TO FINISH FIRST TIME BOOT... TIME ELAPSED: {time_elapsed}s")
        # Elapse some time in waiting so that ASAv can finish first time boot. Reserved 30s to call CONFIGURE ASAv.
        time.sleep(100)
        #__________________________________________________________________________________________________________________________
        # INVOKE CONFIGURE ASAv
        configure_asav_invoke_respose = postLaunchActionObject.publish_message(configure_asav_topic_id, configure_asav_payload)
        logger.debug(f"POST LAUNCH ACTION {identifier}: configure_asav_invoke_respose {configure_asav_invoke_respose}")
        if configure_asav_invoke_respose == True:
            logger.info(f"POST LAUNCH ACTION {identifier}: Configure ASAv Function has been called successfully")
            logger.info(f"POST LAUNCH ACTION {identifier} COMPLETED SUCCESSFULLY")
            return f"POST LAUNCH ACTION {identifier} COMPLETED SUCCESSFULLY"
        else:
            logger.error(f"POST LAUNCH ACTION {identifier} UNABLE TO RE-CALL CONFIGURE ASAv FUNCTION, INSTACE WILL BE TERMINATED")
            terminate_response = self.terminate_instance()
            return f"POST LAUNCH ACTION {identifier} UNABLE TO RE-CALL CONFIGURE ASAv FUNCTION, POST LAUNCH ACTION FAILED"

    else:
        logger.info(f"POST LAUNCH ACTION {identifier}: Instance does not belongs to autoscale Instance Pool, No action performed")
        return "Instance does not belongs to autoscale Instance Pool"