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

Name:       constant.py
Purpose:    This is python file for Constant variables
"""

endpoints_for_region = {"eu-frankfurt-1": "https://telemetry-ingestion.eu-frankfurt-1.oraclecloud.com",
                        "us-phoenix-1": "https://telemetry-ingestion.us-phoenix-1.oraclecloud.com",
                        "us-ashburn-1": "https://telemetry-ingestion.us-ashburn-1.oraclecloud.com",
                        "uk-london-1": "https://telemetry-ingestion.uk-london-1.oraclecloud.com",
                        "ca-toronto-1": "https://telemetry-ingestion.ca-toronto-1.oraclecloud.com",
                        "ap-sydney-1": "https://telemetry-ingestion.ap-sydney-1.oraclecloud.com",
                        "ap-melbourne-1": "https://telemetry-ingestion.ap-melbourne-1.oraclecloud.com",
                        "sa-saopaulo-1": "https://telemetry-ingestion.sa-saopaulo-1.oraclecloud.com",
                        "ca-montreal-1": "https://telemetry-ingestion.ca-montreal-1.oraclecloud.com",
                        "sa-santiago-1": "https://telemetry-ingestion.sa-santiago-1.oraclecloud.com",
                        "ap-hyderabad-1": "https://telemetry-ingestion.ap-hyderabad-1.oraclecloud.com",
                        "ap-mumbai-1": "https://telemetry-ingestion.ap-mumbai-1.oraclecloud.com",
                        "ap-osaka-1": "https://telemetry-ingestion.ap-osaka-1.oraclecloud.com",
                        "ap-tokyo-1": "https://telemetry-ingestion.ap-tokyo-1.oraclecloud.com",
                        "eu-amsterdam-1": "https://telemetry-ingestion.eu-amsterdam-1.oraclecloud.com",
                        "me-jeddah-1": "https://telemetry-ingestion.me-jeddah-1.oraclecloud.com",
                        "ap-seoul-1": "https://telemetry-ingestion.ap-seoul-1.oraclecloud.com",
                        "ap-chuncheon-1": "https://telemetry-ingestion.ap-chuncheon-1.oraclecloud.com",
                        "eu-zurich-1": "https://telemetry-ingestion.eu-zurich-1.oraclecloud.com",
                        "me-dubai-1": "https://telemetry-ingestion.me-dubai-1.oraclecloud.com",
                        "uk-cardiff-1": "https://telemetry-ingestion.uk-cardiff-1.oraclecloud.com",
                        "us-sanjose-1": "https://telemetry-ingestion.us-sanjose-1.oraclecloud.com"
                        }


# Encoding constant for password decryption function
ENCODING = "utf-8"

ASAV_SSH_PORT = 22
ASAV_USERNAME = "admin"
DEFAULT_PASSWORD = "cisco123"
USE_PUBLIC_IP_FOR_SSH = True

SCALE_BASED_ON = "Average" #Average/Maximum
