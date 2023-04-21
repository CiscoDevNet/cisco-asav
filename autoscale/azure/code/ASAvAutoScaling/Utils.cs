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
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using System.Threading;

//*****************************************Login to ASA via SSH****************************************
namespace asaSshClient
{
    public class asaSshClientClass
    {
        public string checkAsaStatus(string asaIp, ILogger log)
        {
            string asaUserName = System.Environment.GetEnvironmentVariable("ASA_USERNAME", EnvironmentVariableTarget.Process);
            string asaPassword = System.Environment.GetEnvironmentVariable("ASA_PASSWORD", EnvironmentVariableTarget.Process);
            string lookfor = "logged in to";

            log.LogInformation("ASAv public IP : {0}", asaIp);
            //Ignore Host Key Verification 
            Process ssh = new Process();
            ssh.StartInfo.FileName = "cmd";
            ssh.StartInfo.Arguments = " /c echo y | D:\\home\\site\\wwwroot\\asassh.exe " + asaUserName + "@" + asaIp + " -pw " + asaPassword + "  show version";
            ssh.StartInfo.RedirectStandardOutput = true;
            ssh.StartInfo.RedirectStandardInput = true;
            ssh.StartInfo.RedirectStandardError = true;
            ssh.StartInfo.UseShellExecute = false;

            try
            {
                ssh.Start();
                string outp = ssh.StandardOutput.ReadToEnd();
                string err = ssh.StandardError.ReadToEnd();
                log.LogInformation("checkAsaStatus:::: SSH output : {0}", outp);
                log.LogInformation("checkAsaStatus:::: SSH error: {0}", err);
                ssh.Close();
                if (outp.Contains(lookfor))
                {
                    log.LogWarning("checkAsaStatus:::: Found {0} in ssh output", lookfor);
                    return "READY";
                }
                log.LogWarning("checkAsaStatus:::: Unable to find {0}", lookfor);
                return "WAITING";
            }
            catch
            {
                log.LogError("checkAsaStatus:::: SSH exception");
                return "WAITING";
            }
        }

        public string checkAsaConfiguration(string asaPublicIp, ILogger log)
        {
            string asaUserName = System.Environment.GetEnvironmentVariable("ASA_USERNAME", EnvironmentVariableTarget.Process);
            string asaPassword = System.Environment.GetEnvironmentVariable("ASA_PASSWORD", EnvironmentVariableTarget.Process);

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
            log.LogInformation("checkAsaConfiguration:::: Verifying ASA Configuration");
            inputWriter.WriteLine(cmd);
            Thread.Sleep(1000);
            inputWriter.NewLine = "\n";
            inputWriter.WriteLine("y");

            //enter enable mode
            Thread.Sleep(2000);
            inputWriter.WriteLine("enable");
            Thread.Sleep(2000);
            inputWriter.WriteLine(asaPassword);
            Thread.Sleep(2000);

            //check if enable password is accepted and operation mode has changed
            inputWriter.WriteLine("show interface ip brief | grep Management");
            Thread.Sleep(2000);
            inputWriter.WriteLine("exit");
            inputWriter.WriteLine("exit");

            //Check for configuration errors
            inputWriter.Close();
            string cmdOutput = "";
            string tmp = "";

            while (tmp != null)
            {
                tmp = outputReader.ReadLine();
                cmdOutput += tmp;
            }

            // log.LogInformation("Output : {0}", cmdOutput);
            asaSsh.Close();

            if (cmdOutput.Contains("up") && cmdOutput.Contains("DHCP"))
            {
                log.LogInformation("checkAsaConfiguration:::: enable mode is setup");
                return "SUCCESS";
            }
            else
            {
                log.LogError("checkAsaConfiguration:::: Failed to enter enable mode");
                return "ERROR";
            }
        }

        public string asaConfig(string asaPublicIp, string configCmd, ILogger log)
        {
            string asaUserName = System.Environment.GetEnvironmentVariable("ASA_USERNAME", EnvironmentVariableTarget.Process);
            string asaPassword = System.Environment.GetEnvironmentVariable("ASA_PASSWORD", EnvironmentVariableTarget.Process);

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
            log.LogInformation("asaConfig:::: ASA configuration started via SSH");
            inputWriter.WriteLine(cmd);
            Thread.Sleep(1000);
            inputWriter.WriteLine("y");

            //enter enable mode
            Thread.Sleep(2000);
            inputWriter.WriteLine("enable");
            Thread.Sleep(2000);
            inputWriter.WriteLine(asaPassword);

            //configuration
            inputWriter.WriteLine(cmd);
            Thread.Sleep(1000);
            inputWriter.WriteLine("Y");
            Thread.Sleep(1000);
            inputWriter.WriteLine(configCmd);
            Thread.Sleep(1000);
            inputWriter.WriteLine("write memory");
            Thread.Sleep(2000);
            inputWriter.Close();
            asaSsh.Close();
            log.LogInformation("asaConfig:::: asaConfig completed");
            return "SUCCESS";
        }
    }
}

