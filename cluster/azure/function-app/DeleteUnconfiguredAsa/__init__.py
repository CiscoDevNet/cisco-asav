import os
import time
import logging as log
import azure.functions as func
from SharedCode import azure_utils as azutils


def main(req: func.HttpRequest):
    operationDelay = 90
    deleteFaultyAsa = os.environ.get("DELETE_FAULTY_ASA")

    if "YES" != deleteFaultyAsa:
        log.info("DeleteUnConfiguredASA:::: Feature to delete configured ASA is not enabled")
        return func.HttpResponse("NOACTION", status_code=200)

    req_body = req.get_json()
    asa_name = req_body.get("asaDevName")
    if asa_name is None:
        log.info("DeleteUnConfiguredASA:::: Invalid ASA instance name")
        log.error("ERROR: Invalid ASA instance name for DeleteUnConfiguredASA")
        return func.HttpResponse("ERROR: Invalid ASA instance name", status_code=400)

    vMachineScaleSet = azutils.get_vmss_obj()

    vmssCapacity = vMachineScaleSet.sku.capacity
    log.info("DeleteUnConfiguredASA:::: Current VMSS Capacity : {}".format(vmssCapacity))

    instanceid = None
    vmss_vms = azutils.get_vmss_vm_list()
    for vm in vmss_vms:
        if asa_name == vm.name:
            instanceid = vm.id.split("/")[-1]
            break

    if instanceid is None:
        return func.HttpResponse("SUCCESS", status_code=200)

    azutils.vmss_vm_delete(instanceid)
    time.sleep(operationDelay)

    # Check delete status
    vMachineScaleSet = azutils.get_vmss_obj()
    log.info("DeleteUnConfiguredASA:::: Post delete instance VMSS Capacity : {}".format(vMachineScaleSet.sku.capacity))

    if vMachineScaleSet.sku.capacity != (vmssCapacity - 1):
        log.error("DeleteUnConfiguredASA:::: Failed delete instance operation (vmss capacity: {})".format(vMachineScaleSet.sku.capacity))
        log.error(
            "ERROR: Failed delete instance operation. Don't worry, Azure may be taking longer time to delete, but eventually it may delete")
        return func.HttpResponse("ERROR: Failed delete instance operation", status_code=400)

    return func.HttpResponse("SUCCESS", status_code=200)
