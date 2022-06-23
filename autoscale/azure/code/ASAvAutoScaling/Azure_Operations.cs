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
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Microsoft.Azure.Management.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent.Core;
using Microsoft.Azure.Management.ResourceManager.Fluent.Authentication;
using Microsoft.Azure.Management.Compute;
using Microsoft.Azure.Management.Compute.Models;
using Microsoft.Azure.Management.Network;
using NetworkManagementClient = Microsoft.Azure.Management.Network.NetworkManagementClient;
using asaSshClient;

namespace ASAAutoScaleManager
{
    //***************************************Scale Out*****************************************************************
    public static class AsaScaleOut
    {
        [FunctionName("AsaScaleOut")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            int operationDelay = 60000; //1min
            var resoureGroupName = System.Environment.GetEnvironmentVariable("RESOURCE_GROUP_NAME", EnvironmentVariableTarget.Process);
            var vmScalesetName = System.Environment.GetEnvironmentVariable("VMSS_NAME", EnvironmentVariableTarget.Process);
            var subscriptionId = System.Environment.GetEnvironmentVariable("SUBSCRIPTION_ID", EnvironmentVariableTarget.Process);

            string COUNT = req.Query["COUNT"];
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            COUNT = COUNT ?? data?.COUNT;

            int asaCountInt = Convert.ToInt32(COUNT);
            log.LogWarning("AsaScaleOut:::: count str {0}, count int {1}", COUNT, asaCountInt);
            log.LogWarning("AsaScaleOut:::: ASA ScaleOut Started (RG : {0}, VMSS: {1}, Count: {2})", resoureGroupName.ToString(), vmScalesetName.ToString(), asaCountInt);

            var factory = new AzureCredentialsFactory();
            var msiCred = factory.FromMSI(new MSILoginInformation(MSIResourceType.AppService), AzureEnvironment.AzureGlobalCloud);
            var azure = Azure.Configure().WithLogLevel(HttpLoggingDelegatingHandler.Level.Basic).Authenticate(msiCred).WithSubscription(subscriptionId);

            var vMachineScaleSet = azure.VirtualMachineScaleSets.GetByResourceGroup(resoureGroupName, vmScalesetName);

            log.LogWarning("AsaScaleOut:::: Current VMSS Capacity : {0}", vMachineScaleSet.Capacity.ToString());
            var computeManagementClient = new ComputeManagementClient(msiCred) { SubscriptionId = azure.SubscriptionId };
            var update = computeManagementClient.VirtualMachineScaleSets.CreateOrUpdateWithHttpMessagesAsync(resoureGroupName, vmScalesetName,
                    new VirtualMachineScaleSet
                    {
                        Location = vMachineScaleSet.RegionName,
                        Overprovision = false,
                        Sku = new Sku
                        {
                            Capacity = vMachineScaleSet.Capacity + asaCountInt,
                            Name = vMachineScaleSet.Sku.Sku.Name,
                            Tier = vMachineScaleSet.Sku.Sku.Tier
                        }
                    });
            log.LogInformation("AsaScaleOut:::: ASA Scale Out Started... Please wait");
            update.Wait(operationDelay);
            log.LogInformation("AsaScaleOut:::: ASA Scale Out Status : {0}", update.Status.ToString());

            if ("WaitingForActivation" != update.Status.ToString())
            {
                log.LogError("AsaScaleOut:::: ScaleOut Operation failed (Status : {0})", update.Status.ToString());
                return (ActionResult)new BadRequestObjectResult("ERROR: ScaleOut Operation failed");
            }

            vMachineScaleSet = azure.VirtualMachineScaleSets.GetByResourceGroup(resoureGroupName, vmScalesetName);
            log.LogWarning("AsaScaleOut:::: Post ScaleOut VMSS Capacity : {0}", vMachineScaleSet.Capacity.ToString());
            return (ActionResult)new OkObjectResult("SUCCESS");
        }
    }

    //***************************************Scale-In*****************************************************************
    public static class AsaScaleIn
    {
        [FunctionName("AsaScaleIn")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            int operationDelay = 90000; //1.5min
            var resoureGroupName = System.Environment.GetEnvironmentVariable("RESOURCE_GROUP_NAME", EnvironmentVariableTarget.Process);
            var vmScalesetName = System.Environment.GetEnvironmentVariable("VMSS_NAME", EnvironmentVariableTarget.Process);
            var subscriptionId = System.Environment.GetEnvironmentVariable("SUBSCRIPTION_ID", EnvironmentVariableTarget.Process);
            string instanceid = req.Query["instanceid"];
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            instanceid = instanceid ?? data?.instanceid;
            int vmssCapacity = 0;
 
            if (null == instanceid)
            {
                log.LogError("AsaScaleIn:::: Invalid ASA Instance Id for ScaleIn");
                return (ActionResult)new BadRequestObjectResult("ERROR: Invalid ASA Instance Id for ScaleIn");
            }

            log.LogWarning("AsaScaleIn:::: ASA Scale-In Started (RG : {0}, VMSS: {1}, ASA InstanceId to Delete: {2} )", resoureGroupName.ToString(), vmScalesetName.ToString(), instanceid);

            var factory = new AzureCredentialsFactory();
            var msiCred = factory.FromMSI(new MSILoginInformation(MSIResourceType.AppService), AzureEnvironment.AzureGlobalCloud);
            var azure = Azure.Configure().WithLogLevel(HttpLoggingDelegatingHandler.Level.Basic).Authenticate(msiCred).WithSubscription(subscriptionId);

            var vMachineScaleSet = azure.VirtualMachineScaleSets.GetByResourceGroup(resoureGroupName, vmScalesetName);

            vmssCapacity = vMachineScaleSet.Capacity;
            log.LogInformation("AsaScaleIn:::: Current VMSS Capacity : {0}", vmssCapacity);

            var computeManagementClient = new ComputeManagementClient(msiCred) { SubscriptionId = azure.SubscriptionId };
            //var del = computeManagementClient.VirtualMachineScaleSetVMs.DeleteWithHttpMessagesAsync(resoureGroupName, vmScalesetName, instanceid).Result;
            var del = computeManagementClient.VirtualMachineScaleSetVMs.DeleteWithHttpMessagesAsync(resoureGroupName, vmScalesetName, instanceid);
            del.Wait(operationDelay);

            vMachineScaleSet = azure.VirtualMachineScaleSets.GetByResourceGroup(resoureGroupName, vmScalesetName);
            log.LogInformation("AsaScaleIn:::: Post ScaleIn VMSS Capacity : {0}", vMachineScaleSet.Capacity.ToString());

            if ((vmssCapacity - 1) != vMachineScaleSet.Capacity)
            {
                log.LogError("AsaScaleIn:::: Failed ScaleIn Operation (vmss capacity: {0})", vMachineScaleSet.Capacity);
                return (ActionResult)new BadRequestObjectResult("ERROR: Failed ScaleIn Operation. Don't worry, Azure may be taking longer time to delete, but eventually it may delete");
            }
            
            return (ActionResult)new OkObjectResult("SUCCESS");
        }
    }

    //***************************************Get Public IP of new ASA*****************************************************************
    public static class AsaGetPubIp
    {
        [FunctionName("GetAsaPublicIp")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            var subscriptionId = System.Environment.GetEnvironmentVariable("SUBSCRIPTION_ID", EnvironmentVariableTarget.Process);

            string COUNT = req.Query["COUNT"];
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            COUNT = COUNT ?? data?.COUNT;

            string TYPE = req.Query["TYPE"];
            string requestBody1 = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data1 = JsonConvert.DeserializeObject(requestBody);
            TYPE = TYPE ?? data?.TYPE;
 
            int asaCountInt = Convert.ToInt32(COUNT);
            int index = 1;

            if("REGULAR" == TYPE)
            {
                log.LogWarning("GetAsaPublicIp:::: This is regular scale-out ");
            }
            else if("INIT" == TYPE)
            {
                log.LogWarning("GetAsaPublicIp:::: This is initial deployment");
            }
            else
            {
                return (ActionResult)new BadRequestObjectResult("ERROR: Invalid request TYPE");
            }
            var resoureGroupName = System.Environment.GetEnvironmentVariable("RESOURCE_GROUP_NAME", EnvironmentVariableTarget.Process);
            var vmScalesetName = System.Environment.GetEnvironmentVariable("VMSS_NAME", EnvironmentVariableTarget.Process);
            var networkInterfaceName = System.Environment.GetEnvironmentVariable("MNGT_NET_INTERFACE_NAME", EnvironmentVariableTarget.Process);   
            var ipConfigurationName = System.Environment.GetEnvironmentVariable("MNGT_IP_CONFIG_NAME", EnvironmentVariableTarget.Process); 
            var publicIpAddressName = System.Environment.GetEnvironmentVariable("MNGT_PUBLIC_IP_NAME", EnvironmentVariableTarget.Process); 

            log.LogWarning("GetAsaPublicIp:::: Getting Public IP of new ASA (RG : {0}, VMSS: {1} )", resoureGroupName.ToString(), vmScalesetName.ToString());
            log.LogInformation("GetAsaPublicIp:::: Network Interface name : {0}, IP Configuration Name : {1}, Public IP Address Name : {2}", networkInterfaceName, ipConfigurationName, publicIpAddressName);

            var factory = new AzureCredentialsFactory();
            var msiCred = factory.FromMSI(new MSILoginInformation(MSIResourceType.AppService), AzureEnvironment.AzureGlobalCloud);
            var azure = Azure.Configure().WithLogLevel(HttpLoggingDelegatingHandler.Level.Basic).Authenticate(msiCred).WithSubscription(subscriptionId);

            var NmClient = new NetworkManagementClient(msiCred) { SubscriptionId = azure.SubscriptionId };
            var interfaceList = NmClient.NetworkInterfaces.ListVirtualMachineScaleSetNetworkInterfaces(resoureGroupName, vmScalesetName);
            string vmindex = "";
            string tmpVmindex = "";
            int intVmindex = 0;
            var vmlist = azure.VirtualMachineScaleSets.GetByResourceGroup(resoureGroupName, vmScalesetName);
            var vmStatus = "";
            var tmpVmName = "ERROR";

            //ToDo: This logic should be simplified with just one loop of vmlist, no need of interfaceList
            foreach (var netInterface in interfaceList)
            {
                if ((netInterface.IpConfigurations[0].PublicIPAddress != null))
                {
                    var tmpIntfName = netInterface.IpConfigurations[0].PublicIPAddress.Id.Split('/').GetValue(12);
                    var tmpConfigName = netInterface.IpConfigurations[0].PublicIPAddress.Id.Split('/').GetValue(14);
                    var tmpPubIpName = netInterface.IpConfigurations[0].PublicIPAddress.Id.Split('/').GetValue(16);

                    if ((tmpIntfName.ToString() == networkInterfaceName) && (tmpConfigName.ToString() == ipConfigurationName) && (tmpPubIpName.ToString() == publicIpAddressName))
                    {
                        vmindex = netInterface.IpConfigurations[0].PublicIPAddress.Id.Split('/').GetValue(10).ToString();
                        vmStatus = "ON";
                        foreach (var vm in vmlist.VirtualMachines.List())
                        {
                            if (vm.InstanceId == vmindex)
                            {
                                if(null == vm.PowerState)
                                {
                                    vmStatus = "OFF";
                                }
                                if (null != vm.Name)
                                {
                                    tmpVmName = vm.Name;
                                }
                                break;
                            }
                        }
                        if ("OFF" == vmStatus)
                        {
                            log.LogError("GetAsaPublicIp:::: VM index :{0} is in unknown state..skip", vmindex);
                             continue;
                        }
                        //Azure bug, some times even deleted VMs are still attahed to network interfaces
                        if("ERROR" == tmpVmName)
                        {
                            log.LogError("GetAsaPublicIp:::: VM index :{0} name not found...skip", vmindex);
                            continue;
                        }
                        if ("INIT" == TYPE)
                        {
                            if (index == asaCountInt)
                            {
                                //index >100 is just to safegaurd this loop..its has no other logic
                                break;
                            }                            
                            index++;
                        }
                        else
                        {
                            //Azure bug: Some time it will mix indexes and does not preserve sequence
                            if (Convert.ToInt32(vmindex) < intVmindex)
                            {
                                log.LogWarning("GetAsaPublicIp:::: Azure index jumbling detected");
                                vmindex = intVmindex.ToString();
                            }
                            else
                            {                                
                                intVmindex = Convert.ToInt32(vmindex);
                                log.LogInformation("GetAsaPublicIp:::: Assigning vmindex = {0}", vmindex);
                            }

                        }
                    }
                }
            }

            var publicIp = NmClient.PublicIPAddresses.GetVirtualMachineScaleSetPublicIPAddress(resoureGroupName, vmScalesetName, vmindex, networkInterfaceName, ipConfigurationName, publicIpAddressName).IpAddress;
            if (null == publicIp)
            {
                log.LogError("GetAsaPublicIp:::: Unable to get Public IP of new ASA (index {0}", vmindex);
                return (ActionResult)new BadRequestObjectResult("ERROR: Unable to get Public IP of new ASA");
            }
            log.LogInformation("GetAsaPublicIp:::: Public IP of New ASA (VM index {0}) = {1}", vmindex, publicIp);

            //++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#if false
            //Use this if we need outside interface public ip
            var outpubIp = NmClient.PublicIPAddresses.GetVirtualMachineScaleSetPublicIPAddress(resoureGroupName, vmScalesetName, vmindex, "outsideNic", ipConfigurationName, "outsidePublicIP").IpAddress;
            if (null == outpubIp)
            {
                log.LogError("GetAsaPublicIp:::: Unable to get outside interface Public IP of new ASA (index {0}", vmindex);
                return (ActionResult)new BadRequestObjectResult("ERROR: Unable to get outside interface Public IP of new ASA");
            }
            log.LogInformation("GetAsaPublicIp:::: Outside Interface Public IP of New ASA (VM index {0}) = {1}", vmindex, outpubIp);
#endif
            //++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            //find VM name from index
            string vmname = "";
            string privateIp = "";
            var vmss = azure.VirtualMachineScaleSets.GetByResourceGroup(resoureGroupName, vmScalesetName);
            foreach (var vm in vmss.VirtualMachines.List())
            {
                if(vm.InstanceId == vmindex)
                {
                    vmname = vm.Name;
                    foreach(var netintf in vm.ListNetworkInterfaces())
                    {
                        privateIp = netintf.PrimaryPrivateIP;
                        break;
                    }
                    break;
                }
            }

            var commandStr = "{ \"asaDevName\": \"" + vmname + "\", \"asaPublicIp\": \"" + publicIp + "\", \"asaPrivateIp\" : \"" + privateIp + "\"  }";
            return (ActionResult)new OkObjectResult(commandStr);
        }
    }

    //---------------------------------------Delete configured ASAv-------------------
    public static class DeleteUnConfiguredASA
    {
        [FunctionName("DeleteUnConfiguredASA")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            var delBadASA = System.Environment.GetEnvironmentVariable("DELETE_FAULTY_ASA", EnvironmentVariableTarget.Process);
            var subscriptionId = System.Environment.GetEnvironmentVariable("SUBSCRIPTION_ID", EnvironmentVariableTarget.Process);
            string asaPublicIp = req.Query["asaPublicIp"];
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            asaPublicIp = asaPublicIp ?? data?.asaPublicIp;
            string asaDevName = req.Query["asaDevName"];
            string requestBodyName = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic dataName = JsonConvert.DeserializeObject(requestBody);
            asaDevName = asaDevName ?? data?.asaDevName;

            if ("YES" != delBadASA)
            {
                log.LogWarning("DeleteUnConfiguredASA:::: Feature to delete configured ASA is not enabled");
                return (ActionResult)new OkObjectResult("NO Action");
            }

            //log.LogWarning("DeleteUnConfiguredASA:::: Checking if {0} is configured", asaDevName);

            //Check for configuration errors
            //var asaSshClient = new asaSshClientClass();
           //var configStatus = asaSshClient.checkAsaConfiguration(asaPublicIp, log);
           //----This function is executed by Orchestrator only if configuration fails, hence no need to check any status---
           // if ("ERROR" == configStatus)
           if(true)
            {
                log.LogError("DeleteUnConfiguredASA:::: ASA {0} is not configured correctly .. Deleting it from Azure", asaDevName);
                //de-register license
                log.LogInformation("DeleteUnConfiguredASA:::: Config cleanup");
                var asaSsh = new asaSshClientClass();
                //nothing can be done if this fails
                asaSsh.asaConfig(asaPublicIp, "license smart deregister", log);

                var resoureGroupName = System.Environment.GetEnvironmentVariable("RESOURCE_GROUP_NAME", EnvironmentVariableTarget.Process);
                var vmScalesetName = System.Environment.GetEnvironmentVariable("VMSS_NAME", EnvironmentVariableTarget.Process);
                var factory = new AzureCredentialsFactory();
                var msiCred = factory.FromMSI(new MSILoginInformation(MSIResourceType.AppService), AzureEnvironment.AzureGlobalCloud);
                var azure = Azure.Configure().WithLogLevel(HttpLoggingDelegatingHandler.Level.Basic).Authenticate(msiCred).WithSubscription(subscriptionId);

                var vmss = azure.VirtualMachineScaleSets.GetByResourceGroup(resoureGroupName, vmScalesetName);
                foreach (var vm in vmss.VirtualMachines.List())
                {
                    if (asaDevName == vm.Name)
                    {
                        log.LogWarning("DeleteUnConfiguredASA:::: Found {0} in Azure, Azure instance Id : {1}", vm.Name, vm.InstanceId);
                        var computeManagementClient = new ComputeManagementClient(msiCred) { SubscriptionId = azure.SubscriptionId };
                        int operationDelay = 30000; //30sec
                        var del = computeManagementClient.VirtualMachineScaleSetVMs.DeleteWithHttpMessagesAsync(resoureGroupName, vmScalesetName, vm.InstanceId);
                        del.Wait(operationDelay);
                        log.LogWarning("DeleteUnConfiguredASA:::: Deleted ASA {0}", vm.Name);
                        return (ActionResult)new BadRequestObjectResult("DELETED unconfigured ASA");
                    }
                }
                log.LogError("DeleteUnConfiguredASA:::: Unable to find {0} in Azure VMSS", asaDevName);
                return (ActionResult)new BadRequestObjectResult("Unable to find this ASA in Azure");
            }
            else
            {
                log.LogInformation("ASA is configured, No Action needed");
                return (ActionResult)new OkObjectResult("NO Action");
            }
        }
     }
}