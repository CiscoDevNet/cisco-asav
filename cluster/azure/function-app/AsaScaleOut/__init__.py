import os
import logging as log
import azure.functions as func
from SharedCode import azure_utils as azutils


def main(req: func.HttpRequest):
    operationDelay = 60
    resourceGroupName = os.environ.get("RESOURCE_GROUP_NAME")
    vmScalesetName = os.environ.get("VMSS_NAME")

    req_body = req.get_json()
    COUNT = req_body.get('COUNT')
    asaCountInt = int(COUNT)

    log.info("AsaScaleOut:::: count {} ".format(COUNT))
    log.info(
        "AsaScaleOut:::: ASA ScaleOut Started (RG : {}, VMSS: {}, Count: {}".format(resourceGroupName, vmScalesetName,
                                                                                    COUNT))

    vMachineScaleSet = azutils.get_vmss_obj()
    log.info("AsaScaleOut:::: Current VMSS Capacity : {}".format(vMachineScaleSet.sku.capacity))

    update = azutils.vmss_create_or_update(location=vMachineScaleSet.location, overprovision="false",
                                           name=vMachineScaleSet.sku.name, tier=vMachineScaleSet.sku.tier,
                                           capacity=(vMachineScaleSet.sku.capacity + asaCountInt))

    # Update status from create_update pending
    log.info("AsaScaleOut:::: ASA Scale Out Started... Please wait")
    update.wait(operationDelay)
    log.info("AsaScaleOut:::: ASA Scale Out Status : {}".format(update.status()))

    if update.status() != "InProgress":
        log.info("AsaScaleOut:::: ScaleOut Operation failed (Status : {})".format(update.status()))
        log.error("ERROR: ScaleOut Operation failed")
        return func.HttpResponse("ERROR: ScaleOut Operation failed", status_code=400)

    vMachineScaleSet = azutils.get_vmss_obj()
    log.warning("AsaScaleOut:::: Post ScaleOut VMSS Capacity : {}".format(vMachineScaleSet.sku.capacity))
    return func.HttpResponse("SUCCESS", status_code=200)
