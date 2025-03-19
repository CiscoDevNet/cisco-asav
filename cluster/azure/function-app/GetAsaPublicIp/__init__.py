import os
import logging as log
import azure.functions as func
from SharedCode import azure_utils as azutils


def main(req: func.HttpRequest):
    resourceGroupName = os.environ.get("RESOURCE_GROUP_NAME")
    vmScalesetName = os.environ.get("VMSS_NAME")
    networkInterfaceName = os.environ.get("MNGT_NET_INTERFACE_NAME")
    ipConfigurationName = os.environ.get("MNGT_IP_CONFIG_NAME")
    publicIpAddressName = os.environ.get("MNGT_PUBLIC_IP_NAME")

    req_body = req.get_json()
    COUNT = req_body.get('COUNT')
    TYPE = req_body.get('TYPE')

    asaCountInt = int(COUNT)
    index = 1

    if TYPE == "REGULAR":
        log.warning("GetAsaPublicIP:::: This is regular scale-out ")
    elif TYPE == "INIT":
        log.warning("GetAsaPublicIP:::: This is initial deployment")
    else:
        log.error("ERROR: Invalid request TYPE")
        return func.HttpResponse("ERROR: Invalid request TYPE", status_code=400)

    log.warning("GetAsaPublicIP:::: Getting Public IP of new ASA (RG : {}, VMSS: {} )".format(resourceGroupName,
                                                                                              vmScalesetName))
    log.info(
        "GetAsaPublicIP:::: Network Interface name : {}, IP Configuration Name : {}, Public IP Address Name : {}".format(
            networkInterfaceName, ipConfigurationName, publicIpAddressName))

    tmpVmName = "ERROR"
    vmName = ""
    vmlist = azutils.get_vmss_vm_list()
    interfaceList = azutils.get_vmss_intf_list()
    vmindex = ""
    intVmindex = 0
    privateIP = ""
    # only for Mgmt Interface
    for interface in interfaceList:
        if interface.name == networkInterfaceName:
            privateIP = interface.ip_configurations[0].private_ip_address
            intfID = interface.ip_configurations[0].id  # config id
            idList = intfID.split("/")

            vmindex = idList[10]

            vmStatus = "ON"

            for v in vmlist:
                vmId = v.id
                vmName = v.name
                vmIdList = vmId.split("/")
                vmInstanceIndex = vmIdList[-1]

                if vmInstanceIndex == vmindex:
                    if v.instance_view.statuses[1].code != "PowerState/running":
                        vmStatus = "OFF"
                    if v.name is not None:
                        tmpVmName = v.name
                    break

            if vmStatus == "OFF":
                log.error("GetAsaPublicIP:::: VM index :{} is in unknown state..skip".format(vmindex))
                continue
            if tmpVmName == "ERROR":
                log.error("GetAsaPublicIP:::: VM index :{} VM name not found...skip".format(vmindex))
                continue
            if TYPE == "INIT":
                if asaCountInt == index:
                    break
                index = index + 1
            else:
                if int(vmindex) < intVmindex:
                    log.warning("GetAsaPublicIP:::: Azure index jumbling detected")
                    vmindex = intVmindex
                else:
                    intVmindex = int(vmindex)

    publicIP = azutils.get_vmss_public_ip(vmindex, networkInterfaceName, ipConfigurationName, publicIpAddressName)

    if publicIP is None:
        log.error("GetAsaPublicIP:::: Unable to get Public IP of new ASAv (index {0}".format(vmindex))
        return func.HttpResponse("ERROR: Unable to get Public IP of new ASAv", status_code=400)

    log.info("GetAsaPublicIP:::: Public IP of New ASA (VM index {}) = {}".format(vmindex, publicIP))
    log.info("GetAsaPublicIP:::: Private IP of New ASA (VM index {}) = {}".format(vmindex, privateIP))

    commandStr = "{ \"asaDevName\": \"" + vmName + "\", \"asaPublicIp\": \"" + publicIP + "\", \"asaPrivateIp\" : \"" + privateIP + "\"  }"
    return func.HttpResponse(commandStr, status_code=200)
