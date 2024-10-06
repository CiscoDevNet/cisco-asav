#!/bin/bash
# Copyright (c) 2024 Cisco Systems Inc or its affiliates.
#
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set +x
INTERACTIVE_FLAG=" -it"
PRIVILEGED_FLAG=" --sysctl net.ipv6.conf.all.disable_ipv6=0 --privileged --cap-add=NET_RAW "
NAME_FLAG="asac"
CPU_FLAG=" -e ASAC_CPUS="1""
MEMORY_FLAG=" -e ASAC_MEMORY="2048M""
ASAC_ENV_FLAG=" -e ASA_DOCKER="1" -e ASAC_STANDALONE_MODE="1" -e ASAC_ROOT_PRIVILEGE="1" "

HOST_NETWORK=1
ASAC_DATA_NW_1=
ASAC_DATA_NW_2=

# One or more volume mappings can be added by setting VOLUMES="-v <host path>:<container path>"
VOLUMES="${VOLUMES:-}"

function usage()
{
    echo "Usage:"
    echo "To deploy with host networks:" 
    echo "    ./start_asac_docker.sh <docker_image_tag>"
    echo "To deploy with docker networs:" 
    echo "    ./start_asac_docker.sh <docker_image_tag> <docker_network_1> <docker_network_2> <docker_network_3>"
    exit 1
}

if [ -z "$1" ]; then
    usage
    exit 1
else
    IMAGE_VERSION="$1"
fi

if [ -z "$2" ]; then
    echo "Docker networks are not provided, considering host networks"
    ASAC_NETWORK="host"
    HOST_NETWORK=0
else
    echo "Docker networks are provided.."
    ASAC_NETWORK="$2"
    if [ ! -z "$3" ]; then
        ASAC_DATA_NW_1="$3"
	if [ ! -z "$4" ]; then
            ASAC_DATA_NW_2="$4"
	fi
    fi
fi

function check_docker()
{
     local installed_version=
 
     if ! which docker &> /dev/null
     then
         echo ERROR: docker is not installed, please install docker.
         echo Acceptable docker version >= ${MIN_DOCKER_VERSION}
         echo Instructions to install docker can be found at https://docs.docker.com/install/
         exit 1
     fi
 
     #Check if docker is running
     if ! docker info &> /dev/null
     then
         echo "Docker is installed but is not running."
         exit 1
     fi
 
     installed_version=$(docker version --format '{{.Server.Version}}')
     #echo "Docker version ${installed_version}" 
 }
 
 
 function set_volumes() {
     
     if [ ! -s "$(pwd)/day0-config" ]; then
         echo "day0-config file is not-present/empty in the pwd."
         exit 1
     fi

     if [ ! -s "$(pwd)/interface-config" ]; then
         echo "interface-config file is not-present/emprty in the pwd."
         exit 1
     fi

     VOLUMES+=" -v /dev:/dev"
     VOLUMES+=" -v $(pwd)/day0-config:/asac-day0-config/day0-config:Z"
     VOLUMES+=" -v $(pwd)/interface-config:/mnt/disk0/interface-config/interface-config:Z"
 }


function check_docker_networks() {

     if [ ${HOST_NETWORK} ]; then
         return 0
     fi

     net_names=( ${ASAC_NETWORK} ${ASAC_DATA_NW_1} ${ASAC_DATA_NW_2} )
     for val in "${net_names[@]}"
     do
	 if [ -z ${val} ]; then
             break
         fi
         NETWORK_INSPECT="docker network inspect ${val}"
	 $NETWORK_INSPECT > /dev/null 2>&1
         if [[ $? -ne 0 ]]; then
             echo "${val} docker network not present"
             exit $?
         fi
     done
}

 # Main
 
check_docker
set_volumes
check_docker_networks

 DOCKER_CREATE_CMD="docker create ${INTERACTIVE_FLAG} \
         ${PRIVILEGED_FLAG} 
	 --network ${ASAC_NETWORK} \
	 --name ${NAME_FLAG} \
	 ${CPU_FLAG} \
	 ${MEMORY_FLAG} \
         ${VOLUMES} \
	 ${ASAC_ENV_FLAG} \
         --entrypoint /asa/bin/lina_launcher.sh \
         ${IMAGE_VERSION}"


 echo "Starting ASA Container..."
 echo $DOCKER_CREATE_CMD
 echo
 echo "Mount Points:"
 echo "----------------------------------------------------------------------------------------"
 (
     echo "Host Container"
     echo "---- ---------"
     echo $DOCKER_CREATE_CMD | grep -E -o '\-v [^[:space:]]*' | sed 's/-v//' | awk -F ":" '{print$1,$2}'
 ) | column -t
 echo "----------------------------------------------------------------------------------------"
 echo
 
 $DOCKER_CREATE_CMD > /dev/null 2>&1
 if [[ $? -ne 0 ]]; then
     echo "Error creating ASAc Docker!"
     exit $?
 fi

 if [ ${HOST_NETWORK} ] ; then
     if [ ! -z ${ASAC_DATA_NW_1} ]; then
         DOCKER_INSIDE_NETWORK_CONNECT_CMD="docker network connect ${ASAC_DATA_NW_1} ${NAME_FLAG}"
         echo $DOCKER_INSIDE_NETWORK_CONNECT_CMD
         $DOCKER_INSIDE_NETWORK_CONNECT_CMD
     fi 

     if [ ! -z ${ASAC_DATA_NW_2} ]; then
         DOCKER_OUTSIDE_NETWORK_CONNECT_CMD="docker network connect ${ASAC_DATA_NW_2} ${NAME_FLAG}"
         echo $DOCKER_OUTSIDE_NETWORK_CONNECT_CMD
         $DOCKER_OUTSIDE_NETWORK_CONNECT_CMD
     fi

 fi

 DOCKER_START_CMD="docker start ${NAME_FLAG}" 
 echo $DOCKER_START_CMD
 $DOCKER_START_CMD > /dev/null 2>&1
 if [[ $? -ne 0 ]]; then
     echo "Error creating ASAc Docker!"
     exit $?
 fi
