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
using System.Diagnostics;
using System.Threading;
using asaSshClient;

namespace ASAAutoScaleManager
{
    public static class ConfigureASAv
    {
        [FunctionName("ConfigureASAv")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            string asaUserName = System.Environment.GetEnvironmentVariable("ASA_USERNAME", EnvironmentVariableTarget.Process);
            string asaPassword = System.Environment.GetEnvironmentVariable("ASA_PASSWORD", EnvironmentVariableTarget.Process);
            string setUniqueHostName = System.Environment.GetEnvironmentVariable("SET_UNIQUE_HOST_NAME", EnvironmentVariableTarget.Process);
            string configFile = System.Environment.GetEnvironmentVariable("ASAV_CONFIG_FILE", EnvironmentVariableTarget.Process);

            string asaPublicIp = req.Query["asaPublicIp"];
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            asaPublicIp = asaPublicIp ?? data?.asaPublicIp;
            string asaDevName = req.Query["asaDevName"];
            string requestBodyName = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic dataName = JsonConvert.DeserializeObject(requestBody);
            asaDevName = asaDevName ?? data?.asaDevName;

            log.LogInformation("ConfigureASAv:::: Configuring ASA {0}", asaDevName);

            //Starting Information for process like its path, use system shell i.e. control process by system etc.
            ProcessStartInfo psi = new ProcessStartInfo("cmd");

            //set process attributes
            psi.UseShellExecute = false;
            psi.ErrorDialog = false;
            psi.CreateNoWindow = true;
            psi.WindowStyle = ProcessWindowStyle.Hidden;
            //redirect all standard inout to program
            psi.RedirectStandardError = true;
            psi.RedirectStandardInput = true;
            psi.RedirectStandardOutput = true;

            //create the process with above info and start it
            Process asaSsh = new Process();
            asaSsh.StartInfo = psi;
            asaSsh.Start();

            //link the streams
            StreamWriter inputWriter = asaSsh.StandardInput;
            StreamReader outputReader = asaSsh.StandardOutput;
            StreamReader errorReader = asaSsh.StandardError;

            //send command to cmd prompt and wait for command to execute with thread sleep
            string cmd = "D:\\home\\site\\wwwroot\\asassh.exe -ssh " + asaUserName + "@" + asaPublicIp + " -pw " + asaPassword;
            //log.LogInformation("cmd: {0}", cmd);
            log.LogInformation("ConfigureASAv:::: ASA configuration started via SSH");
            inputWriter.WriteLine(cmd);
            Thread.Sleep(1000);
            inputWriter.WriteLine("y");

            //enter enable mode
            Thread.Sleep(2000);
            inputWriter.WriteLine("enable");
            Thread.Sleep(2000);
            inputWriter.WriteLine(asaPassword);
            Thread.Sleep(2000);
            inputWriter.WriteLine(asaPassword);
            Thread.Sleep(2000);

            //if scp is required, disable strict host key check
            if (configFile.ToLower().Contains("scp:"))
            {
                log.LogInformation("ConfigureASAv :::: Enabling scp file copy");
                inputWriter.WriteLine("conf t");
                Thread.Sleep(2000);
                inputWriter.WriteLine("Y");
                Thread.Sleep(2000);
                inputWriter.WriteLine("no ssh stricthostkeycheck");
                Thread.Sleep(2000);
            }
            //copy configuration
            cmd = "copy /noconfirm " + configFile + " running-config";
          //  log.LogInformation("ConfigureASAv :::: cmd: {0}", cmd);
          
            inputWriter.WriteLine(cmd);
            Thread.Sleep(2000);

            if(configFile.ToLower().Contains("scp:"))
            {
                //enable strict host host key check again
                inputWriter.WriteLine("ssh stricthostkeycheck");
                Thread.Sleep(2000);
            }
/*
            inputWriter.WriteLine("");
            Thread.Sleep(1000);
            inputWriter.WriteLine("");
            Thread.Sleep(1000);
            inputWriter.WriteLine("");
            Thread.Sleep(2000);
*/
            //write configuration to memory
            inputWriter.WriteLine("write memory");
            Thread.Sleep(2000);

            //Check for configuration errors
            var asaSshClient = new asaSshClientClass();
            var configStatus = asaSshClient.checkAsaConfiguration(asaPublicIp, log);

            if ("ERROR" == configStatus)
            {
                log.LogError("ConfigureASAv:::: enable mode is NOT activated");
                return (ActionResult)new StatusCodeResult(StatusCodes.Status500InternalServerError);
            }

            inputWriter.Close();
            string cmdOutput = "";
            string tmp = "";

            while (tmp != null)
            {
                tmp = outputReader.ReadLine();
                cmdOutput += tmp;
            }

            if (cmdOutput.Contains("ERROR"))
            {
                log.LogError("checkAsaConfiguration:::: Found error in configuration : {0}", cmdOutput.Replace(asaPassword, "*******"));
                return (ActionResult)new StatusCodeResult(StatusCodes.Status500InternalServerError);
            }
            asaSsh.Close();

            log.LogInformation("ConfigureASAv:::: Configuration is successful");
            return (ActionResult)new OkObjectResult("SUCCESS");
        }
    }

    //-----------------------------------------------------------------------------------------------------------------------------------------------------------
    //Wait till ASA is ready for SSH
    public static class waitForAsaToComeUp
    {
        [FunctionName("waitForAsaToComeUp")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {

            //get input from http request
            string asaPublicIp = req.Query["asaPublicIp"];
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            asaPublicIp = asaPublicIp ?? data?.asaPublicIp;
            string asaDevName = req.Query["asaDevName"];
            string requestBodyName = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic dataName = JsonConvert.DeserializeObject(requestBody);
            asaDevName = asaDevName ?? data?.asaDevName;

            log.LogInformation("waitForAsaToComeUp:::: Waiting for {0} (IP: {1}) to come up", asaDevName, asaPublicIp );

            var asaSsh = new asaSshClientClass();

            var status = asaSsh.checkAsaStatus(asaPublicIp, log);

            return (ActionResult)new OkObjectResult(status);
        }
    }

    //-----------------------------------------------------------------------------------------------------------------------------------------------------------
    //Disable health probe
    public static class stopNewConnections
    {
        [FunctionName("stopNewConnections")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {

            string asaUserName = System.Environment.GetEnvironmentVariable("ASA_USERNAME", EnvironmentVariableTarget.Process);
            string asaPassword = System.Environment.GetEnvironmentVariable("ASA_PASSWORD", EnvironmentVariableTarget.Process);

            string asaPublicIp = req.Query["asaPublicIp"];
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            asaPublicIp = asaPublicIp ?? data?.asaPublicIp;

            string strOutput = String.Empty;
            String strErrors = String.Empty;
            //Starting Information for process like its path, use system shell i.e. control process by system etc.
            ProcessStartInfo psi = new ProcessStartInfo("cmd");

            //set process attributes
            psi.UseShellExecute = false;
            psi.ErrorDialog = false;
            psi.CreateNoWindow = true;
            psi.WindowStyle = ProcessWindowStyle.Hidden;
            //redirect all standard inout to program
            psi.RedirectStandardError = true;
            psi.RedirectStandardInput = true;
            psi.RedirectStandardOutput = true;
            //create the process with above info and start it
            Process asaSsh = new Process();
            asaSsh.StartInfo = psi;
            asaSsh.Start();

            //link the streams
            StreamWriter inputWriter = asaSsh.StandardInput;
            StreamReader outputReader = asaSsh.StandardOutput;
            StreamReader errorReader = asaSsh.StandardError;

            //send command to cmd prompt and wait for command to execute with thread sleep
            string cmd = "D:\\home\\site\\wwwroot\\asassh.exe -ssh " + asaUserName + "@" + asaPublicIp + " -pw " + asaPassword;
            log.LogInformation("stopNewConnections:::: cmd: {0}", cmd);
            log.LogInformation("stopNewConnections:::: ASA configuration started to disable health probe");
            inputWriter.WriteLine(cmd);
            Thread.Sleep(1000);
            inputWriter.WriteLine("y");

            Thread.Sleep(2000);
            inputWriter.WriteLine("enable");
            Thread.Sleep(2000);
            inputWriter.WriteLine(asaPassword);
            Thread.Sleep(2000);
            inputWriter.WriteLine("conf t");
            Thread.Sleep(2000);
            inputWriter.WriteLine("Y");
            Thread.Sleep(2000);
            //disable ssh
            inputWriter.WriteLine("no ssh 168.63.129.0 255.255.255.0 outside");
            Thread.Sleep(1000);
            inputWriter.WriteLine("no ssh 168.63.129.0 255.255.255.0 inside");
            Thread.Sleep(1000);
            //Check for configuration errors
            inputWriter.Close();
            log.LogInformation("stopNewConnections:::: Disabled health Probe");
     
            return (ActionResult)new OkObjectResult("SUCCESS");
           
        }
    }

    //-------------------------------------------------------------------------------------------------------------------------------------------
    //Cleanup before deleting (scale-In ASAv)
    public static class CleanupASAvConfiguration
    {
        [FunctionName("CleanupASAvConfiguration")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            string asaPublicIp = req.Query["asaPublicIp"];
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            asaPublicIp = asaPublicIp ?? data?.asaPublicIp;
                       
            //de-register license
            var asaSsh = new asaSshClientClass();
            //nothing can be done if this fails
            asaSsh.asaConfig(asaPublicIp, "license smart deregister", log);

            log.LogInformation("CleanupASAvConfiguration:::: License Cleanup completed");
            return (ActionResult)new OkObjectResult("SUCCESS");
        }
    }

    //--------------------------------------------------------------------------------------------------------------------------------------------------
    //Check ASAv License status
    public static class CheckASAvLicenseConfig
    {
        [FunctionName("CheckASAvLicenseConfig")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            string asaUserName = System.Environment.GetEnvironmentVariable("ASA_USERNAME", EnvironmentVariableTarget.Process);
            string asaPassword = System.Environment.GetEnvironmentVariable("ASA_PASSWORD", EnvironmentVariableTarget.Process);
            string checkLicensing = System.Environment.GetEnvironmentVariable("PERFORM_LICENSE_CHECK", EnvironmentVariableTarget.Process);

            string asaPublicIp = req.Query["asaPublicIp"];
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            asaPublicIp = asaPublicIp ?? data?.asaPublicIp;
            string asaDevName = req.Query["asaDevName"];
            string requestBodyName = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic dataName = JsonConvert.DeserializeObject(requestBody);
            asaDevName = asaDevName ?? data?.asaDevName;

            log.LogInformation("CheckASAvLicenseConfig:::: Checking License configuration on ASA {0}", asaDevName);
            if("YES" != checkLicensing)
            {
                log.LogInformation("CheckASAvLicenseConfig:::: License configuration check is not enabled..nothing to do");
                return (ActionResult)new OkObjectResult("SUCCESS");
            }

            //Starting Information for process like its path, use system shell i.e. control process by system etc.
            ProcessStartInfo psi = new ProcessStartInfo("cmd");

            //set process attributes
            psi.UseShellExecute = false;
            psi.ErrorDialog = false;
            psi.CreateNoWindow = true;
            psi.WindowStyle = ProcessWindowStyle.Hidden;
            //redirect all standard inout to program
            psi.RedirectStandardError = true;
            psi.RedirectStandardInput = true;
            psi.RedirectStandardOutput = true;

            //create the process with above info and start it
            Process asaSsh = new Process();
            asaSsh.StartInfo = psi;
            asaSsh.Start();

            //link the streams
            StreamWriter inputWriter = asaSsh.StandardInput;
            StreamReader outputReader = asaSsh.StandardOutput;
            StreamReader errorReader = asaSsh.StandardError;

            //send command to cmd prompt and wait for command to execute with thread sleep
            string cmd = "D:\\home\\site\\wwwroot\\asassh.exe -ssh " + asaUserName + "@" + asaPublicIp + " -pw " + asaPassword;
            inputWriter.WriteLine(cmd);
            Thread.Sleep(1000);
            inputWriter.WriteLine("y");

            //enter enable mode
            Thread.Sleep(2000);
            inputWriter.WriteLine("enable");
            Thread.Sleep(2000);
            inputWriter.WriteLine(asaPassword);
            Thread.Sleep(2000);

            //copy configuration
            cmd = "show license summary | grep Status";
            inputWriter.WriteLine(cmd);
            Thread.Sleep(2000);

            inputWriter.Close();
            string cmdOutput = "";
            string tmp = "";

            while (tmp != null)
            {
                tmp = outputReader.ReadLine();
                cmdOutput += tmp;
            }

            if (!cmdOutput.Contains("Status: REGISTERED"))
            {
                log.LogWarning("CheckASAvLicenseConfig::::License not yet applied : {0}", cmdOutput.Replace(asaPassword, "*******"));
                return (ActionResult)new StatusCodeResult(StatusCodes.Status500InternalServerError);
            }
            asaSsh.Close();

            log.LogInformation("CheckASAvLicenseConfig:::: Licensing is successful : {0}", cmdOutput.Replace(asaPassword, "*******"));
            return (ActionResult)new OkObjectResult("SUCCESS");
        }
    }


}