import os
import traceback
import azure.functions as func
import logging as log
from SharedCode import azure_utils as azutils
from datetime import timedelta


def main(req: func.HttpRequest):
    try:
        log.warning("AutoScaleManager:: Checking to see if scaling is required")
        subscriptionId = os.environ.get("SUBSCRIPTION_ID")
        resourceGroupName = os.environ.get("RESOURCE_GROUP_NAME")
        vmScalesetName = os.environ.get("VMSS_NAME")
        minASACount = int(os.environ.get("MIN_ASA_COUNT"))
        maxASACount = int(os.environ.get("MAX_ASA_COUNT"))
        sampleTimeMin = int(os.environ.get("SAMPLING_TIME_MIN"))
        scaleOutThreshold = float(os.environ.get("SCALE_OUT_THRESHOLD"))
        scaleInThreshold = float(os.environ.get("SCALE_IN_THRESHOLD"))
        initialDeployMethod = os.environ.get("INITIAL_DEPLOYMENT_MODE")
        scalingPolicy = os.environ.get("SCALING_POLICY")

        # Getting vmss details and vmss vm list
        vmss = azutils.get_vmss_obj()
        vmss_vms = azutils.get_vmss_vm_list()
        vmss_resourceId = vmss.id

        if vmss_resourceId is None:
            log.error("AutoScaleManager:: Unable to get VM Scale Set ID")
            return func.HttpResponse("ERROR: Unable to get VM Scale Set ID", status_code=400)

        currentVmCapacity = vmss.sku.capacity
        log.warning("AutoScaleManager:: Current VM Scale Set capacity: {}".format(currentVmCapacity))

        # If the VMSS capacity is '0' consider this as first deployment and spawn 'minimum ASA count' at a time
        if currentVmCapacity == 0 and minASACount != 0:
            log.warning(
                "AutoScaleManager:: Current VM Scale Set capacity is 0, considering it as initial deployment (Minimum ASAv count needed : {})".format(
                    minASACount))
            if initialDeployMethod == "BULK":
                log.warning("AutoScaleManager:: Selected Initial deployment mode is Bulk")
                log.warning("AutoScaleManager:: Deploying {} ASAv instances in scale set.".format(minASACount))
                cmdStr = "{ \"COMMAND\": \"SCALEOUT\", \"COUNT\": \"" + str(minASACount) + "\", \"TYPE\": \"INIT\" }"
                return func.HttpResponse(cmdStr, status_code=200)

            else:
                log.warning(
                    "AutoScaleManager:: Selected Initial deployment mode is Individual, bringing up ASAv instances one after another")
                cmdStr = "{ \"COMMAND\": \"SCALEOUT\", \"COUNT\": \"1\", \"TYPE\": \"REGULAR\"}"
                return func.HttpResponse(cmdStr, status_code=200)

        # If VM Scale set current capacity is less than minimum ASAv count, we need to scale out
        if currentVmCapacity < minASACount:
            log.warning(
                "AutoScaleManager:: Current VM Scale Set capacity({}) is less than minimum ASAv count({}), Scaling out".format(
                    currentVmCapacity, minASACount))
            cmdStr = "{ \"COMMAND\": \"SCALEOUT\", \"COUNT\": \"1\", \"TYPE\": \"REGULAR\"}"
            return func.HttpResponse(cmdStr, status_code=200)

        ##################################################### Scaling decisions based on metrics #####################################################

        log.info("Scale Out threshold: {}, Scale In threshold: {}".format(scaleOutThreshold, scaleInThreshold))
        # Checking if scale out threshold is equal to or less than scale in threshold
        if scaleOutThreshold == scaleInThreshold:
            log.warning("AutoScaleManager:: scale-out and scale-in thresholds are same, disabling autoscaling")
            return func.HttpResponse("NOACTION", status_code=200)
        elif scaleOutThreshold < scaleInThreshold:
            log.error(
                "AutoScaleManager:: Scale Out threshold ({}) is less than or equal to Scale In threshold ({}), please specify correct values".format(
                    scaleOutThreshold, scaleInThreshold))
            return func.HttpResponse("ERROR: ScaleOut threshold is less than or equal to ScaleIn threshold",
                                     status_code=400)

        log.warning("AutoScaleManager:: Scaling policy selected during deployment : {}".format(scalingPolicy))
        sampleIntervalMin = timedelta(
            minutes=sampleTimeMin)  # Need to validate : supported values - PT1M,PT5M,PT15M,PT30M,PT1H,PT6H,PT12H,P1D
        metric_client = azutils.get_monitor_metric_client()
        groupCpuUsage = 0
        scaleInRejectFlag = False
        minAsaCpuUsage = 9999
        leastLoadedAsa = ""
        leastLoadedAsaIndex = ""

        if scalingPolicy == "POLICY-2":
            log.info("AutoScaleManager:: Scaling Policy-2 is selected. Getting average CPU Utilization of Scale set.")
            vmss_metrics = metric_client.metrics.list(resource_uri=vmss.id, interval=sampleIntervalMin,
                                                      metricnames="Percentage CPU", aggregation="Average")
            for item in vmss_metrics.value:
                for series in item.timeseries:
                    for data in series.data:
                        if data.average is not None:
                            groupCpuUsage = data.average
                            log.debug("AutoScaleManager:: Group CPU average usage : {}".format(groupCpuUsage))
            log.info("AutoScaleManager:: Group CPU average usage : {}".format(groupCpuUsage))

        for vm in vmss_vms:
            asaCpuUsage = 0
            vm_metrics = metric_client.metrics.list(resource_uri=vm.id, interval=sampleIntervalMin,
                                                    metricnames="Percentage CPU", aggregation="Average")
            for item in vm_metrics.value:
                for series in item.timeseries:
                    for data in series.data:
                        if data.average is not None:
                            asaCpuUsage = data.average
                            log.debug("AutoScaleManager:: ASAv CPU average usage : {}".format(asaCpuUsage))
            log.info("AutoScaleManager:: Average CPU Utilization of VM {} in last {} minutes is {}".format(vm.name,
                                                                                                           sampleTimeMin,
                                                                                                           asaCpuUsage))

            # Store the name of ASAv with minimum utilization to scale-in if needed
            if asaCpuUsage < minAsaCpuUsage:
                minAsaCpuUsage = asaCpuUsage
                leastLoadedAsa = vm.name
                leastLoadedAsaIndex = vm.id

            if scalingPolicy == "POLICY-1":
                # Average Usage of Individual instance
                consolidatedCpuUsage = asaCpuUsage

            elif scalingPolicy == "POLICY-2":
                consolidatedCpuUsage = groupCpuUsage

            else:
                log.error("AutoScaleManager:: Invalid Scaling Policy {}".format(scalingPolicy))
                return func.HttpResponse("ERROR: Invalid Scaling Policy", status_code=400)

            # If CPU utilization is greater than scale-out threshold then scale-out
            if consolidatedCpuUsage > scaleOutThreshold:
                # If current scale set capacity is equal to max ASA count, do nothing
                # If current scale set capacity is more than max ASA count (Ideally, should never happen), do nothing
                if currentVmCapacity >= maxASACount:
                    log.warning(
                        "AutoScaleManager:: NO ACTION, Current scale set capacity is {}, which is greater than or equal to max ASA count ({}). No action required.".format(
                            currentVmCapacity, maxASACount))
                    return func.HttpResponse("NOACTION", status_code=200)

                scaleStr = "{ \"COMMAND\": \"SCALEOUT\", \"COUNT\": \"1\", \"TYPE\": \"REGULAR\" }"
                return func.HttpResponse(scaleStr, status_code=200)

            # If any VM's CPU utilization is greater than scale-in threshold then scale-in is not required
            elif asaCpuUsage > scaleInThreshold:
                scaleInRejectFlag = True
                log.warning(
                    "AutoScaleManager:: NO ACTION, CPU utilization of {} is {}, which greater than scale in threshold, scaling in is not required".format(
                        vm.name, asaCpuUsage))

        # If scaleInRejectFlag is not set, it means all the VMs' CPU and Memory Utilization is less than or equal to Scale-In threshold
        # We will consider only the least CPU consuming ASAv for Scale-In operation
        if not scaleInRejectFlag:
            # If current capacity is less than or equal to minimum ASA count required then scale-in should not be done
            if currentVmCapacity <= minASACount:
                log.warning(
                    "AutoScaleManager:: Scale-In needed but currect VMSS capacity ({}) is less than or equal to minimum ASA count ({}) needed. No action taken.".format(
                        currentVmCapacity, minASACount))
                return func.HttpResponse("NOACTION", status_code=200)

            networkInterfaceName = os.environ.get("MNGT_NET_INTERFACE_NAME")
            ipConfigurationName = os.environ.get("MNGT_IP_CONFIG_NAME")
            publicIpAddressName = os.environ.get("MNGT_PUBLIC_IP_NAME")

            idx = leastLoadedAsaIndex.split("/")[-1]

            publicIp = azutils.get_vmss_public_ip(idx, networkInterfaceName, ipConfigurationName, publicIpAddressName)
            log.warning(
                "AutoScaleManager:: SCALING IN, CPU Utilization of all the ASAs is less than or equal to CPU Scale-In threshold ({}).".format(
                    scaleInThreshold))

            log.warning(
                "AutoScaleManager:: Least loaded ASAv is {} with utilization {}".format(leastLoadedAsa, minAsaCpuUsage))
            scaleStr = "{ \"COMMAND\": \"SCALEIN\", \"asaDevName\": \"" + leastLoadedAsa + "\", \"asaPublicIp\": \"" + publicIp + "\", \"instanceid\" : \"" + idx + "\"  }"
            return func.HttpResponse(scaleStr, status_code=200)

        log.warning("AutoScaleManager:: ASA VMSS utilization is within threshold. No action needed")
        return func.HttpResponse("NOACTION", status_code=200)

    except Exception as e:
        log.error("AutoScaleManager:: Exception occurred : {}".format(traceback.format_exc()))
        return func.HttpResponse("AutoScaleManager:: Exception occurred : {}".format(traceback.format_exc()), status_code=500)
