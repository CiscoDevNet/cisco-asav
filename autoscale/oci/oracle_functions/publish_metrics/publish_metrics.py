"""
Copyright (c) 2021 Cisco Systems Inc or its affiliates.

All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
--------------------------------------------------------------------------------

Name:       publish_metrics.py
Purpose:    This python file is used for publishing the ASAv CPU usage and unhealthy vms count
            These classes will be initialized in the oracle function
"""

# Import System Libraries
import io
import logging
import oci
import os
import re
import socket
import sys
import time
import json
import requests
import base64

from fdk import response

# Import Local libraries
from asav import ParamikoSSH
import constants as const

# Logger Initialization
logging.basicConfig(force=True, level="INFO")
logging.getLogger("paramiko").setLevel(logging.WARNING)
logger = logging.getLogger()


class publishMetrics:

    def __init__(self, signer, compartment_id, region, instance_pool_id, metric_namespace, metric_resource_grp, cpu_metric_name, asav_password,
                                healthcheck_metric_name, elb_id, elb_bs_name, ilb_id, ilb_bs_name):
        self.compartment_id = compartment_id
        self.instance_pool_id = instance_pool_id
        self.service_endpoint = const.endpoints_for_region[region]
        self.oci_compute_obj = oci.core.ComputeManagementClient(config={}, signer=signer)
        self.instance_obj = oci.core.ComputeClient(config={}, signer=signer)
        self.lb_client_obj = oci.load_balancer.LoadBalancerClient(config={}, signer=signer)
        self.virtual_network_client = oci.core.VirtualNetworkClient(config={}, retry_strategy=oci.retry.DEFAULT_RETRY_STRATEGY, signer=signer)
        self.monitoring_client = oci.monitoring.MonitoringClient(config={},service_endpoint=self.service_endpoint, signer=signer)
        self.namespace = metric_namespace
        self.resourceGroup = metric_resource_grp
        self.cpu_metric_name = cpu_metric_name
        self.asav_password = asav_password
        self.healthcheck_metric_name = healthcheck_metric_name
        self.elb_id = elb_id
        self.elb_bs_name = elb_bs_name
        self.ilb_id = ilb_id
        self.ilb_bs_name = ilb_bs_name

    def calculate_cpu_usage_value(self, asav_cpu_usage_list):
        try:
            if not asav_cpu_usage_list:
                logger.error("ASAv CPU usage list is empty.")
                return 0

            scaling_based_on = const.SCALE_BASED_ON.lower()
            logger.info("PUBLISH METRICS : CPU Usage List : {}".format(asav_cpu_usage_list))
            logger.info("PUBLISH METRICS : Scaling action is done based on the \"{}\" value.".format(scaling_based_on))
            if scaling_based_on == "average":
                val = int(sum(asav_cpu_usage_list) / len(asav_cpu_usage_list))
                logger.info("PUBLISH METRICS : The average value of CPU utilization is : {}".format(val))
                return val
            elif scaling_based_on == "maximum":
                val = int(max(asav_cpu_usage_list))
                logger.info("PUBLISH METRICS : The maximum value of CPU utilization is : {}".format(val))
                return val
        except Exception as err:
            raise Exception("PUBLISH METRICS : Unable to calculate the CPU usage for the ASAv instances. \n Error : {}".format(err))

    def fetch_asav_ips(self):
        try:
            asav_ips = []
            # Fetching instances in the instance pool
            instances_list = self.oci_compute_obj.list_instance_pool_instances(self.compartment_id,
                                                                               self.instance_pool_id).data
            logger.info("PUBLISH METRICS : ASAv instance count : {}".format(len(instances_list)))
            if len(instances_list) > 0:
                for instance in instances_list:
                    if instance.state.lower() == "running":
                        # instance_details = self.instance_obj.get_instance(instance.id)
                        vnic_attachments = oci.pagination.list_call_get_all_results(
                            self.instance_obj.list_vnic_attachments,
                            compartment_id=instance.compartment_id,
                            instance_id=instance.id).data
                        vnics = [self.virtual_network_client.get_vnic(va.vnic_id).data for va in vnic_attachments]
                        for vnic in vnics:
                            if vnic.public_ip:
                                asav_ips.append(vnic.public_ip)
            else:
                logger.info("PUBLISH METRICS : No instances in the instance pool")

            return asav_ips

        except Exception as err:
            raise Exception("PUBLISH METRICS : Unable to fetch the ip addresses of the ASAv instances. \n Error : {}".format(err))


    def fetch_cpu_usage_from_asav(self):
        no_of_retry = 3
        cpu_usage_list = []
        command_set_to_show_cpu_usage = {
            "cmd": [
                {
                    "command": "enable",
                    "expect": "Password:"
                },
                {
                    "command": self.asav_password,
                    "expect": "#"
                },
                {
                    "command": "show cpu usage",
                    "expect": "CPU utilization"
                }
            ]
        }
        FAIL = 'FAILURE'
        AUTH_EXCEPTION = 'Authentication Exception Occurred'
        BAD_HOST_KEY_EXCEPTION = 'Bad Key Exception occurred'
        SSH_EXCEPTION = 'SSH Exception Occurred'
        try:
            asav_ip_list = self.fetch_asav_ips()
            logger.info("PUBLISH METRICS : ASAv Instances list : {}".format(asav_ip_list))
            # Check if the list is not empty
            if not asav_ip_list:
                logger.error("PUBLISH METRICS : ASAv Instance List is empty. So the CPU value is published as 0")
                cpu_value = 0
            else:
                for ip in asav_ip_list:
                    logger.info("PUBLISH METRICS : Fetching CPU Utilization for the ASAv : {}".format(ip))
                    cnt_asa = ParamikoSSH(ip, const.ASAV_SSH_PORT, const.ASAV_USERNAME, self.asav_password)
                    for i in range(0, no_of_retry):
                        cmd_output = cnt_asa.handle_interactive_session(command_set_to_show_cpu_usage, const.ASAV_USERNAME, self.asav_password)
                        if cmd_output not in [FAIL, AUTH_EXCEPTION, BAD_HOST_KEY_EXCEPTION, SSH_EXCEPTION]:
                            # pattern = "CPU utilization for 5 seconds\ =\ (.*?)\%;"
                            cpu_usage = int(re.search("CPU utilization for 5 seconds\ =\ (.*?)\%;", cmd_output).group(1))
                            logger.info("PUBLISH METRICS : CPU Utilization value : {}".format(cpu_usage))
                            cpu_usage_list.append(cpu_usage)
                            break
                        else:
                            logger.error("PUBLISH METRICS :Unable to fetch CPU info for the ASAv {}, Error : {}, Retry Count : {}".format(ip, cmd_output, i))
                        time.sleep(10)
                # Calculating CPU value
                cpu_value = self.calculate_cpu_usage_value(cpu_usage_list)

            logger.info("PUBLISH METRICS : CPU Utilization : {}".format(cpu_value))
            return cpu_value
        except Exception as err:
            raise Exception("PUBLISH METRICS : Unable to fetch CPU usage from the ASAv instances. \n Error : {}".format(err))

    def construct_metric_data(self, metric_name, metric_value, metric_unit):
        try:
            post_metric_data = oci.monitoring.models.PostMetricDataDetails(
                metric_data=[
                    oci.monitoring.models.MetricDataDetails(
                        namespace=self.namespace,
                        compartment_id=self.compartment_id,
                        name=metric_name,
                        dimensions={
                            'resourceId': self.compartment_id},
                        datapoints=[
                            oci.monitoring.models.Datapoint(
                                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time())),
                                value=metric_value)
                        ],
                        resource_group=self.resourceGroup,
                        metadata={'unit': metric_unit})]
            )
            return post_metric_data

        except:
            logger.error("Unable to construct post metric data")

    def publish_cpu_metrics(self):
        try:
            cpu_value = self.fetch_cpu_usage_from_asav()
            if cpu_value is None:
                cpu_value = 0

            post_metric_data_details = self.construct_metric_data(self.cpu_metric_name, cpu_value, 'Percentage')
            post_metric_data_response = self.monitoring_client.post_metric_data(post_metric_data_details)
            logger.info("PUBLISH METRICS : Post Metric data Response : {}".format(post_metric_data_response.data))

        except Exception as err:
            post_metric_data_details = self.construct_metric_data(self.cpu_metric_name, 0, 'Percentage')
            post_metric_data_response = self.monitoring_client.post_metric_data(post_metric_data_details)
            logger.error("PUBLISH METRICS : Post Metric data Response : {}".format(post_metric_data_response.data))

    def get_backends_health(self, loadbalancer_id, backendset_name):
        try:
            bs_health_status = self.lb_client_obj.get_backend_set_health(load_balancer_id=loadbalancer_id, backend_set_name=backendset_name).data
            return bs_health_status
        except Exception as err:
            raise Exception("PUBLISH METRICS : Unable to get health status of the loadbalancer backends. Error : {}".format(err))


    def publish_health_check_data(self):
        try:

            elb_backends_health = self.get_backends_health(self.elb_id, self.elb_bs_name)
            if elb_backends_health is not None:
                elb_critical_backends = elb_backends_health.critical_state_backend_names
                elb_critical_ips_list = set([elb_backend.split(":")[0] for elb_backend in elb_critical_backends])
                elb_unhealthy_vm_count = len(elb_critical_ips_list)
            else:
                elb_unhealthy_vm_count = 0

            ilb_backend_health = self.get_backends_health(self.ilb_id, self.ilb_bs_name)
            if ilb_backend_health is not None:
                ilb_critical_backends = ilb_backend_health.critical_state_backend_names
                ilb_critical_ips_list = set([ilb_backend.split(":")[0] for ilb_backend in ilb_critical_backends])
                ilb_unhealthy_vm_count = len(ilb_critical_ips_list)
            else:
                ilb_unhealthy_vm_count = 0

            unhealthy_vm_count = max(elb_unhealthy_vm_count, ilb_unhealthy_vm_count)
            logger.info("Unhealthy VM Count : {}".format(unhealthy_vm_count))
            post_metric_data_details = self.construct_metric_data(self.healthcheck_metric_name, unhealthy_vm_count, 'count')
            post_metric_data_response = self.monitoring_client.post_metric_data(post_metric_data_details)
            logger.info("PUBLISH METRICS : Post Metric data Response : {}".format(post_metric_data_response.data))

        except Exception as err:
            raise Exception("Unable to update health check data. Error : {}".format(err))


def handler(ctx, data: io.BytesIO = None):
    try:
        logger.debug("PUBLISH METRICS : Handler function is invoked")
    except (Exception, ValueError) as ex:
        logger.error("PUBLISH METRICS : ERROR IN PARSING JSON PAYLOAD: " + format(ex))
        return None

    try:
        environmentVariables = ctx.Config()

        # Parameter used to PUBLISH metrics
        compartmentId = environmentVariables["compartment_id"]
        region = environmentVariables["region"]
        instancePoolId = environmentVariables["instance_pool_id"]
        metricNamespaceName = environmentVariables["metric_namespace_name"]
        resourceGroupName = environmentVariables["resource_group_name"]
        cpuMetricName = environmentVariables["cpu_metric_name"]
        # asav_password = environmentVariables["password"]
        # Parameters used to post unhealthy VMs
        healthcheckMetricName = environmentVariables["healthcheck_metric_name"]
        elbId = environmentVariables["elb_id"]
        elbBackendSetName = environmentVariables["elb_backend_set_name"]
        ilbId = environmentVariables["ilb_id"]
        ilbBackendSetName = environmentVariables["ilb_backend_set_name"]
        # ASAv Password decryption related info
        asavEncryptedPassword = environmentVariables["encrypted_password"]
        cryptEndpoint = environmentVariables["cryptographic_endpoint"]
        master_key_id = environmentVariables["master_key_id"]

    except Exception as e:
        logger.error("PUBLISH METRICS : Error while retrieving environment variables. Error : {0}".format(e))
        return None

    try:
        logger.debug("PUBLISH METRICS : Signer invoke")
        signer = oci.auth.signers.get_resource_principals_signer()
    except Exception as e:
        logger.error("PUBLISH METRICS : ERROR IN OBTAINING SIGNER. Error : {}".format(e))
        return None

    try:
        kms_client = oci.key_management.KmsCryptoClient(config={}, signer=signer, service_endpoint=cryptEndpoint)
        decrypt_response = kms_client.decrypt(
            decrypt_data_details=oci.key_management.models.DecryptDataDetails(ciphertext=asavEncryptedPassword,
                                                                              key_id=master_key_id)).data
        asav_password = base64.b64decode(decrypt_response.plaintext).decode('utf-8')

    except Exception as e:
        logger.error("PUBLISH METRICS: ERROR IN DECRYPTING ASAv PASSWORD ERROR: {}".format(e))
        return None

    try:
        logger.debug("PUBLISH METRICS : Creating object for publishMetrics class.")
        obj = publishMetrics(signer, compartmentId, region, instancePoolId, metricNamespaceName,
                                resourceGroupName, cpuMetricName, asav_password, healthcheckMetricName,
                                elbId, elbBackendSetName, ilbId, ilbBackendSetName)
        logger.info("PUBLISH METRICS: Posting ASAv CPU Utilization")
        obj.publish_cpu_metrics()

        logger.info("PUBLISH METRICS: Posting unhealthy VM count")
        obj.publish_health_check_data()
    except Exception as e:
        logger.error("PUBLISH METRICS : Unable to run publish-custom-metrics method.Error: {}".format(e))
        return None

    return response.Response(ctx, response_data=json.dumps({"Message": "Publish Alarm Metrics  is completed Successfully"}), headers={"Content-Type": "application/json"})
