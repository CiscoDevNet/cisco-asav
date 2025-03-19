import os
import time
import logging as log
import azure.functions as func
from SharedCode import azure_utils as azutils


def main(req: func.HttpRequest):
    operationDelay = 90
    resourceGroupName = os.environ.get("RESOURCE_GROUP_NAME")
    vmScalesetName = os.environ.get("VMSS_NAME")

    req_body = req.get_json()
    instanceid = req_body.get("instanceid")

    if instanceid is None:
        log.info("AsaScaleIn:::: Invalid ASA Instance Id for ScaleIn")
        log.error("ERROR: Invalid ASA Instance Id for ScaleIn")
        return func.HttpResponse("ERROR", status_code=400)

    log.info(
        "AsaScaleIn:::: ASA Scale-In Started RG : {}, VMSS: {}, ASA InstanceId to Delete: {} ".format(resourceGroupName,
                                                                                                      vmScalesetName,
                                                                                                      instanceid))

    vMachineScaleSet = azutils.get_vmss_obj()

    vmssCapacity = vMachineScaleSet.sku.capacity
    log.info("AsaScaleIn:::: Current VMSS Capacity : {}".format(vmssCapacity))

    azutils.vmss_vm_delete(instanceid)
    time.sleep(operationDelay)

    # Check delete status
    vMachineScaleSet = azutils.get_vmss_obj()
    log.info("AsaScaleIn:::: Post ScaleIn VMSS Capacity : {}".format(vMachineScaleSet.sku.capacity))

    if vMachineScaleSet.sku.capacity != (vmssCapacity - 1):
        log.error("AsaScaleIn:::: Failed ScaleIn Operation (vmss capacity: {})".format(vMachineScaleSet.sku.capacity))
        log.error(
            "ERROR: Failed ScaleIn Operation. Don't worry, Azure may be taking longer time to delete, but eventually it may delete")
        return func.HttpResponse("ERROR: ScaleIn Operation Failed", status_code=400)

    return func.HttpResponse("SUCCESS", status_code=200)
