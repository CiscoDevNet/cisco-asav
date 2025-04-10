import os
import time
import traceback
import uuid
import logging as log
import azure.functions as func
from azure.storage.queue import QueueClient, TextBase64EncodePolicy, TextBase64DecodePolicy
from SharedCode import azure_utils as azutils
from SharedCode.asav import ASAvInstance


def main(req: func.HttpRequest):
    MAX_RETRIES = 3
    CONFIGURE_ALL = True

    asa_public_ip = None
    try:
        req_body = req.get_json()
        asa_public_ip = req_body.get("asaPublicIp")
        CONFIGURE_ALL = False
    except:
        if not CONFIGURE_ALL:
            log.warning("ConfigureASAv:: Invalid ASA Public IP for ConfigureASAv")
            return func.HttpResponse("ERROR", status_code=500)

    try:

        # get list of VMs
        vm_list = azutils.get_vmss_info()
        configured_asav = get_asadetailsfromqueue()

        config_url = os.environ.get('ASAV_CONFIG_FILE', '')
        monitor_cluster = os.environ.get('MONITOR_CLUSTER', "NO")
        local_file_name = 'Configuration.txt'
        asav_local_file_path = 'disk0:' + local_file_name

        vmss_vm_ip_list = set()
        for vm in vm_list:
            vmss_vm_ip_list.add(vm_list[vm]['MgmtPublic'])

        if CONFIGURE_ALL:
            log.info('Checking cluster state on all nodes with re-enable mode: {}'.format(monitor_cluster))
            if monitor_cluster == "YES":
                configured_asav = []
            try:
                for vm in vm_list:
                    if vm_list[vm]['Status'] != "VM running":
                        log.error("ConfigureASAv:: VM {} is not in running state.".format(vm_list[vm]['MgmtPublic']))
                        continue

                    if vm_list[vm]['MgmtPublic'] in configured_asav:
                        log.info("ConfigureASAv:: Cluster is already enabled on the ASAv instance {}".format(
                            vm_list[vm]['MgmtPublic']))
                        continue

                    asav_obj = ASAvInstance(vm_list[vm], str(uuid.uuid4()))
                    ssh_status = asav_obj.check_asav_ssh_status()
                    log.info("ConfigureASAv:: ASAv Connect Status for ASAv {} : {}".format(vm_list[vm]['MgmtPublic'],
                                                                                           ssh_status))
                    if ssh_status == "SUCCESS":
                        log.info("ConfigureASAv:: Connected to the ASAv Instance : {}. Configuring Enable Password".format(
                            vm_list[vm]['MgmtPublic']))

                        if not check_and_set_enable_password(asav_obj):
                            continue

                        if check_and_enable_cluster(asav_obj, vm_list[vm]):
                            configured_asav.append(vm_list[vm]['MgmtPublic'])
                            put_configured_asav_to_queue('-'.join(set(configured_asav)))
                            log.info("ConfigureASAv:: Configured clustering for ASAv Instance - {}".format(
                                vm_list[vm]['MgmtPublic']))
            except Exception:
                log.error("ConfigureASAv:: Error Occurred : {}".format(traceback.format_exc()))

            if vmss_vm_ip_list.issubset(set(configured_asav)):
                log.info("ConfigureASAv:: Configured all the ASAv Instances in the VMSS!")
                return func.HttpResponse("SUCCESS", status_code=200)
            else:
                unconfigured_asav = vmss_vm_ip_list - set(configured_asav)
                log.error("ConfigureASAv:: Unable to configure the ASAv instances : {}".format(unconfigured_asav))
                return func.HttpResponse("ERROR: Unable to configure the ASAv instances", status_code=500)

        vm_to_configure = None
        for vm in vm_list:
            if vm_list[vm]['MgmtPublic'] == asa_public_ip:
                if vm_list[vm]['Status'] != "VM running":
                    log.error("ConfigureASAv:: VM {} is not in running state.".format(vm_list[vm]['MgmtPublic']))
                    return func.HttpResponse("ERROR", status_code=500)

                if asa_public_ip in configured_asav:
                    log.info("ConfigureASAv:: Cluster is already enabled on the ASAv instance {}".format(
                        vm_list[vm]['MgmtPublic']))
                    return func.HttpResponse("SUCCESS", status_code=200)

                vm_to_configure = vm_list[vm]

        if vm_to_configure is None:
            log.error("ConfigureASAv:: VM {} details not found in vmss.".format(asa_public_ip))
            return func.HttpResponse("ERROR", status_code=500)

        asav_obj = ASAvInstance(vm_to_configure, str(uuid.uuid4()))
        for i in range(MAX_RETRIES):
            ssh_status = asav_obj.check_asav_ssh_status()
            log.info("ConfigureASAv:: ASAv Connect Status for ASAv {} : {}".format(vm_to_configure['MgmtPublic'],
                                                                                   ssh_status))
            if ssh_status == "SUCCESS":
                log.info("ConfigureASAv:: Connected to the ASAv Instance : {}. Configuring Enable Password".format(
                    vm_to_configure['MgmtPublic']))

                for i in range(MAX_RETRIES):
                    if check_and_set_enable_password(asav_obj):
                        break
                    else:
                        continue

                log.info("ConfigureASAv:: Copying the configuration to the ASAv Instance : {}".format(
                    vm_to_configure['MgmtPublic']))
                if config_url:
                    try:
                        if asav_obj.verify_configuration_file_copy(local_file_name) == "SUCCESS":
                            log.info("ConfigureASAv:: ASAv Configuration has been already applied!")
                        elif asav_obj.run_copy_file_running_config(config_url, asav_local_file_path) == "SUCCESS":
                            if asav_obj.verify_configuration_file_copy(local_file_name) == "SUCCESS":
                                log.info("ConfigureASAv:: ASAv Configuration has been applied!")
                    except Exception as e:
                        log.warning("ConfigureASAv:: Failed to copy or verify configuration file : {}".format(
                            traceback.format_exc()))

                log.info("ConfigureASAv:: Checking the status of the cluster")

                if check_and_enable_cluster(asav_obj, vm_to_configure, retries=MAX_RETRIES):
                    configured_asav.append(vm_to_configure['MgmtPublic'])
                    put_configured_asav_to_queue('-'.join(set(configured_asav)))
                    log.info("ConfigureASAv:: Configured clustering for ASAv Instance - {}".format(
                        vm_to_configure['MgmtPublic']))
                    return func.HttpResponse("SUCCESS", status_code=200)
                break
            else:
                log.error("ConfigureASAv:: Unable to Connect to the ASAv instance : {}. Retrying...".format(
                    vm_to_configure['MgmtPublic']))
                time.sleep(20)

        return func.HttpResponse(
            "ERROR: Unable to configure the ASAv instance - {}".format(vm_to_configure['MgmtPublic']), status_code=500)

    except Exception as err:
        log.error("ConfigureASAv:: Error Occurred : {}".format(traceback.format_exc()))
        return func.HttpResponse("ERROR: Error Occurred while configuring ASAv", status_code=500)


def check_and_set_enable_password(asav_obj):
    check_passwd_status = asav_obj.is_passwd_already_set()
    if check_passwd_status == "NOT SET":
        set_pwd_status = asav_obj.set_enable_password()
        log.info("ConfigureASAv:: Status of Enable Password : {}".format(set_pwd_status))
        if set_pwd_status == "SUCCESS":
            log.info("ConfigureASAv:: Enable Password Set Successfully")
            return True
        else:
            log.info("ConfigureASAv:: Error in configuring enable Password.")
            return False

    elif check_passwd_status == "SET":
        log.info("ConfigureASAv:: Enable Password is already set")
        return True

    else:
        return False


def check_and_enable_cluster(asav_obj, vm_to_configure, retries=1):
    if asav_obj.check_and_configure_hostname() != "SUCCESS":
        log.error("ConfigureASAv:: Hostname configuration failed for the ASAv VM {}."
                  .format(vm_to_configure['MgmtPublic']))

    cluster_status = asav_obj.check_asav_cluster_status()
    if cluster_status == "NOT ENABLED":
        log.info("ConfigureASAv:: Enabling cluster on the ASAv : {}".format(vm_to_configure['MgmtPublic']))
        octet = str(vm_to_configure['MgmtPrivate'].split('.')[3])
        for i in range(retries):
            enable_cluster = asav_obj.apply_cluster_config(octet)
            log.info("ConfigureASAv:: Status of the enable Cluster : {}".format(enable_cluster))
            if enable_cluster == "SUCCESS":
                log.info("ConfigureASAv:: Configured clustering for ASAv Instance - {}".format(
                    vm_to_configure['MgmtPublic']))
                return True
            else:
                log.error("ConfigureASAv:: Cluster Configuration failed for the ASAv VM {}."
                          .format(vm_to_configure['MgmtPublic']))

            if retries - 1 > 0:
                log.info("ConfigureASAv:: Retrying...")
                time.sleep(10)

    elif cluster_status == "ENABLED":
        log.info("ConfigureASAv:: Cluster is already enabled on the ASAv : {}".format(
            vm_to_configure['MgmtPublic']))
        return True

    else:
        log.error("ConfigureASAv:: Error in cluster status check. {}".format(cluster_status))
    return False


def get_asadetailsfromqueue():
    constr = os.environ['AzureWebJobsStorage']
    queue = QueueClient.from_connection_string(
        conn_str=constr,
        queue_name="asavdetails",
        message_encode_policy=TextBase64EncodePolicy(),
        message_decode_policy=TextBase64DecodePolicy()
    )
    msg = queue.receive_message()
    if msg is not None:
        return msg["content"].split('-')
    else:
        return []


def put_configured_asav_to_queue(asav_list, ttl=604800):
    constr = os.environ['AzureWebJobsStorage']
    queue = QueueClient.from_connection_string(
        conn_str=constr,
        queue_name="asavdetails",
        message_encode_policy=TextBase64EncodePolicy()
    )
    queue.clear_messages()
    queue.send_message(asav_list, time_to_live=ttl)
    time.sleep(5)
