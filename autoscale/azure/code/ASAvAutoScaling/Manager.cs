//  Copyright (c) 2020 Cisco Systems Inc or its affiliates.
//
//  All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Rest.Azure.OData;
using Microsoft.Azure.Management.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent.Core;
using Microsoft.Azure.Management.ResourceManager.Fluent.Authentication;
using Microsoft.Azure.Management.Monitor;
using Microsoft.Azure.Management.Monitor.Models;
using Microsoft.Azure.Management.Network;
using NetworkManagementClient = Microsoft.Azure.Management.Network.NetworkManagementClient;

/* Scaling Logic:-
 * If current Scale set capacity = 0, Start Scale-Out (increase VM count by 1 or by 'MIN_ASA_COUNT' duration based on 'INITIAL_DEPLOYMENT_MODE'
 * POLICY-1 :  ScaleOut : If any VM's average usage goes beyond 'SCALE_OUT_THRESHLD' for 'SAMPLING_TIME_MIN' duration and current scale set capacity < 'MAX_ASA_COUNT'
 * POLICY-2 :  ScaleOut : If average usage of scaling group goes beyond 'SCALE_OUT_THRESHLD' for 'SAMPLING_TIME_MIN' duration and current scale set capacity < 'MAX_ASA_COUNT'
 * Scale-In :  If all the VM's average usage goes below 'SCALE_IN_THRESHLD' for 'SAMPLING_TIME_MIN' duration and current scale set capacity > 'MIN_ASA_COUNT'
 */

namespace ASAAutoScaleManager
{
    public static class AutoScaleManager
    {
        [FunctionName("AutoScaleManager")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogWarning("AutoScaleManager:::: Task to check Scaling requirement.. Started (ASAv Auto Scale Manager Version : V1.3)");
            var resoureGroupName = System.Environment.GetEnvironmentVariable("RESOURCE_GROUP_NAME", EnvironmentVariableTarget.Process);
            var vmScalesetName = System.Environment.GetEnvironmentVariable("VMSS_NAME", EnvironmentVariableTarget.Process);
            var minASACountStr = System.Environment.GetEnvironmentVariable("MIN_ASA_COUNT", EnvironmentVariableTarget.Process);
            var maxASACountStr = System.Environment.GetEnvironmentVariable("MAX_ASA_COUNT", EnvironmentVariableTarget.Process);
            var sampleTimeMin = System.Environment.GetEnvironmentVariable("SAMPLING_TIME_MIN", EnvironmentVariableTarget.Process);
            var scaleOutThresholdStr = System.Environment.GetEnvironmentVariable("SCALE_OUT_THRESHLD", EnvironmentVariableTarget.Process);
            var scaleInThresholdStr = System.Environment.GetEnvironmentVariable("SCALE_IN_THRESHLD", EnvironmentVariableTarget.Process);
            var initialDeployMethod = System.Environment.GetEnvironmentVariable("INITIAL_DEPLOYMENT_MODE", EnvironmentVariableTarget.Process); //supported STEP / BULK
            var scalingPolicy = System.Environment.GetEnvironmentVariable("SCALING_POLICY", EnvironmentVariableTarget.Process); // POLICY-1 / POLICY-2
            var subscriptionId = System.Environment.GetEnvironmentVariable("SUBSCRIPTION_ID", EnvironmentVariableTarget.Process);

            int minASACount = Convert.ToInt32(minASACountStr);
            int maxASACount = Convert.ToInt32(maxASACountStr);
            double scaleOutThreshold = Convert.ToDouble(scaleOutThresholdStr);
            double scaleInThreshold = Convert.ToDouble(scaleInThresholdStr);
            int currentVmCapacity = 0;
            string scaleStr = "";

            //Reject if scaleOutThreshold < scaleInThreshold
            if(scaleOutThreshold <= scaleInThreshold)
            {
                log.LogError("AutoScaleManager:::: ScaleOut Threshold ({0}) is less than or equal to ScaleIn Threshold ({1}) this is not correct", scaleOutThreshold, scaleInThreshold);
                return (ActionResult)new BadRequestObjectResult("ERROR: ScaleOut threshold is less than or equal to ScaleIn threshold");
            }


            log.LogInformation("AutoScaleManager:::: Sampling Resource Utilization at {0}min Average", sampleTimeMin);

            var factory = new AzureCredentialsFactory();
            var msiCred = factory.FromMSI(new MSILoginInformation(MSIResourceType.AppService), AzureEnvironment.AzureGlobalCloud);
            var azure = Azure.Configure().WithLogLevel(HttpLoggingDelegatingHandler.Level.Basic).Authenticate(msiCred).WithSubscription(subscriptionId);

            string resourceUri = null;
            var vmss = azure.VirtualMachineScaleSets.GetByResourceGroup(resoureGroupName, vmScalesetName);
            resourceUri = vmss.Id;

            if (null == resourceUri)
            {
                log.LogError("AutoScaleManager:::: Unable to get resource uri");
                return (ActionResult)new BadRequestObjectResult("ERROR: Unable to get resource uri");
            }

            currentVmCapacity = vmss.Capacity;
            log.LogWarning("AutoScaleManager:::: Current capacity of VMSS : {0}", currentVmCapacity);

            //If the VMSS capacity is '0' consider this as first deployment and spawn 'minimum ASA count' at a time
            if(( 0 == currentVmCapacity ) && (0 != minASACount))
            {
                log.LogWarning("AutoScaleManager:::: Current VMSS capacity is 0, considering it as first deployment (min ASA count needed : {0}", minASACount);
                if("BULK" == initialDeployMethod)
                {
                    log.LogWarning("AutoScaleManager:::: Selected initial deployment mode is BULK");
                    log.LogWarning("AutoScaleManager:::: Deploying {0} number of ASAvs in scale set", minASACount);
                    scaleStr = "{ \"COMMAND\": \"SCALEOUT\", \"COUNT\": \"" + minASACount + "\", \"TYPE\": \"INIT\" }";
                    return (ActionResult)new OkObjectResult(scaleStr);

                }
                else
                {
                    log.LogWarning("AutoScaleManager:::: BULK method is not selected for initial deployment.. proceeding with STEP");
                    scaleStr = "{ \"COMMAND\": \"SCALEOUT\", \"COUNT\": \"1\", \"TYPE\": \"REGULAR\"}";
                    return (ActionResult)new OkObjectResult(scaleStr);
                }
            }

            //If current capacity is less than minimum ASA count requied then we need to scale-out
            if (currentVmCapacity < minASACount)
            {
                log.LogWarning("AutoScaleManager:::: Current VMSS Capacity({0}) is less than minimum ASA count ({1}) needed.. time to SCALE-OUT", currentVmCapacity, minASACount);
                scaleStr = "{ \"COMMAND\": \"SCALEOUT\", \"COUNT\": \"1\", \"TYPE\": \"REGULAR\"}";
                return (ActionResult)new OkObjectResult(scaleStr);
            }


            //-------------------------------------------------Scaling decission based on Metrics------------------------------------------------------
            var sampleIntervalMin = System.TimeSpan.FromMinutes(Convert.ToDouble(sampleTimeMin));
            MonitorManagementClient metricClient = new MonitorManagementClient(msiCred);
            double asaUsage = 0 ;
            double groupUsage = 0;
            double consolidatedUsage = 0;
            bool scaleInRejectFlag = false;
            double minAsaUsage = 9999;
            string leastLoadedAsa = "";
            string leastLoadedAsaIndex = "";

            log.LogWarning("AutoScaleManager:::: Scaling Policy : {0}", scalingPolicy);
            if("POLICY-2" == scalingPolicy)
            {
                log.LogInformation("AutoScaleManager:::: Scaling Policy-2 Selected..Getting average CPU utilization of scale set");
                var response = await metricClient.Metrics.ListAsync(resourceUri, null, null, sampleIntervalMin, "Percentage CPU", "Average");
                foreach (var metric in response.Value)
                {
                    foreach (var series in metric.Timeseries)
                    {
                        foreach (var point in series.Data)
                        {
                            if (point.Average.HasValue)
                            {
                                groupUsage = point.Average.Value;
                                log.LogDebug("AutoScaleManager:::: avg cpu: {0}", asaUsage);
                            }
                        }
                    }
                }
                log.LogInformation("AutoScaleManager:::: Group average usage : {0}", groupUsage);
            }

            foreach (var vm in vmss.VirtualMachines.List())
            {
                var vmName = vm.Name;                
                asaUsage = 0;
                //Metrics filter
                ODataQuery<MetadataValue> odataFilterMetrics = new ODataQuery<MetadataValue>(string.Format("VMName eq '{0}'", vmName));

                log.LogInformation("AutoScaleManager:::: Getting Metrics for : {0}", vmName);
                var response = await metricClient.Metrics.ListAsync(resourceUri, odataFilterMetrics, null, sampleIntervalMin, "Percentage CPU", "Average");

                foreach (var metric in response.Value)
                {
                    foreach (var series in metric.Timeseries)
                    {
                        foreach (var point in series.Data)
                        {
                            if (point.Average.HasValue)
                            {
                                 asaUsage = point.Average.Value;
                                 log.LogDebug("AutoScaleManager:::: avg cpu: {0}", asaUsage);                               
                            }
                        }
                    }
                }

                log.LogInformation("AutoScaleManager:::: Avg CPU Utilizatio of VM({0}) in last {1}min : {2}%", vmName, sampleTimeMin, asaUsage);

                //Maintain the ASA with minimum utilization to scale-in if needed
                if(asaUsage < minAsaUsage)
                {
                    minAsaUsage = asaUsage;
                    leastLoadedAsa = vmName;
                    leastLoadedAsaIndex = vm.InstanceId;
                }

                if ("POLICY-1" == scalingPolicy)
                {
                    //Average usage of individual Instance
                    consolidatedUsage = asaUsage;
                }
                else if ("POLICY-2" == scalingPolicy)
                {
                    //Scale Set average utilization
                    consolidatedUsage = groupUsage;
                }
                else
                {
                    log.LogError("Invalid Scaling Policy {0}", scalingPolicy);
                    return (ActionResult)new BadRequestObjectResult("ERROR: Invalid Scaling Policy");
                }

                //If CPU utilization is greater than scale-out threshold then Scale-Out
                if (consolidatedUsage > scaleOutThreshold)
                {
                    //If current capacity is equal to max ASA count required then do nothing
                    //If current capacity is more than max ASA count (This should never happen) do nothing
                    if (currentVmCapacity >= maxASACount)
                    {
                        log.LogWarning("AutoScaleManager:::: Current VMSS Capacity({0}) is greater than or equal to max ASA count ({1}) needed.. No action needed", currentVmCapacity, maxASACount);
                        return (ActionResult)new OkObjectResult("NOACTION");
                    }
                    if ("POLICY-1" == scalingPolicy)
                    {
                        log.LogWarning("AutoScaleManager:::: Avg CPU Utilizatio of VM({0}) in last {1}min is {2}% which is greater than ScaleOut threshold({3}%) .. Time to SCALE-OUT", vmName, sampleTimeMin, consolidatedUsage, scaleOutThreshold);
                    }
                    else if ("POLICY-2" == scalingPolicy)
                    {
                        log.LogWarning("AutoScaleManager:::: Avg CPU Utilizatio of Scale Set in last {0}min is {1}% which is greater than ScaleOut threshold({2}%) .. Time to SCALE-OUT", sampleTimeMin, consolidatedUsage, scaleOutThreshold);
                    }
                    scaleStr = "{ \"COMMAND\": \"SCALEOUT\", \"COUNT\": \"1\", \"TYPE\": \"REGULAR\" }";
                    return (ActionResult)new OkObjectResult(scaleStr);
                }
                //If any VM's CPU utilization is greater than scale-in threshold then Scale-In is not needed
                //                       OR
                //Azure does not update metrics as soon as VM is launched, it takes ~20min
                //during this time Azure returns '0' as utilization, we need to ignore this and avoid scale-in (This new VM may be utilized more)
                else if ( (asaUsage > scaleInThreshold) || (0 == asaUsage) )
                {
                    scaleInRejectFlag = true;
                }
            }

            //if scaleInRejectFlag is not set, it means all the VM's CPU utilization is less than or equal to Scale-In threshold
            if (false == scaleInRejectFlag)
            {
                //If current capacity is less than or equal to minimum ASA count requied then scale-in should not be done
                if (currentVmCapacity <= minASACount)
                {
                    log.LogWarning("AutoScaleManager:::: Scale-In needed but Current VMSS Capacity({0}) is less than or equal to minimum ASA count ({1}) needed.. No Action done", currentVmCapacity, minASACount);
                    return (ActionResult)new OkObjectResult("NOACTION");
                }
                var networkInterfaceName = System.Environment.GetEnvironmentVariable("MNGT_NET_INTERFACE_NAME", EnvironmentVariableTarget.Process);
                var ipConfigurationName = System.Environment.GetEnvironmentVariable("MNGT_IP_CONFIG_NAME", EnvironmentVariableTarget.Process);
                var publicIpAddressName = System.Environment.GetEnvironmentVariable("MNGT_PUBLIC_IP_NAME", EnvironmentVariableTarget.Process);

                var NmClient = new NetworkManagementClient(msiCred) { SubscriptionId = azure.SubscriptionId };
                var publicIp = NmClient.PublicIPAddresses.GetVirtualMachineScaleSetPublicIPAddress(resoureGroupName, vmScalesetName, leastLoadedAsaIndex, networkInterfaceName, ipConfigurationName, publicIpAddressName).IpAddress;

                log.LogWarning("AutoScaleManager:::: CPU Utilization of all the ASA's is less than or equal to Scale-In threshold({0}%).. Time to SCALE-IN", scaleInThreshold);
                log.LogWarning("AutoScaleManager:::: Least loaded ASA is : {0} with Utilization : {1}%", leastLoadedAsa, minAsaUsage);
                scaleStr = "{ \"COMMAND\": \"SCALEIN\", \"asaDevName\": \"" + leastLoadedAsa + "\", \"asaPublicIp\": \"" + publicIp + "\", \"instanceid\" : \"" + leastLoadedAsaIndex + "\"  }";
            
                return (ActionResult)new OkObjectResult(scaleStr);
            }
            //Scaling not needed
            log.LogWarning("AutoScaleManager:::: ASA scaleset utilization is within threshold.. no action needed");
            return (ActionResult)new OkObjectResult("NOACTION");
        }
    }
}
