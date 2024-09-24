# Standalone ASA Container on Kubernetes and Docker

# 1. Scope
This document describes the deployment steps for Standalone ASA container with docker and K8S environment on VMWare.
Following are the scope of ASAc deployments on VMWare environment.

1.	K8S with macvlan CNI Framework
2.	Docker host with macvlan networks

This feature is focusing on the integration/validation of ASAc with Opensource Kubernetes framework since most of the container orchestrator is based out of Kubernetes solution.

# 2. Prerequisite
# 2.1	Kubernetes Prerequisite
Following are the prerequisites to deploy ASAc on K8S framework,

1.	Ubuntu 20.04.6 LTS on both master and worker nodes.
2.	Worker node should contain dedicated three virtual interfaces for ASAc to use, apart from the worker node’s     management interface which is used for ssh access to worker node.
2.	Hugepages should be enabled on worker node.
4.	K8S framework v1.26 and Docker v24.0.5 are used for validation.
5.	Calico CNI is used as POD management.
6.	Multus with macvlan is used for ASA container interfaces.

# 2.2	Docker host Prerequisite
Following are the prerequisites to deploy ASAc on docker framework,


1.	Ubuntu 20.04.6 LTS on both master and worker nodes.
2.	Docker host should contain dedicated three virtual interfaces for ASAc to use, apart from the docker host’s management interface which is used for ssh access.
3.	Hugepages should be enabled on docker host.
4.	Docker v24.0.5 with macvlan network is used for validation.

# 3	Deployment models
The Kubernetes or Docker environment can be used to deploy standalone ASA container, the below section describes the required prerequisite from environment and ASA container deployment.

# 3.1	Kubernetes Framework

![Picture 1](https://wwwin-github.cisco.com/storage/user/19835/files/3af0f38e-4341-4e6b-a7d9-5678d992ccf1)
 
# 3.1.1	K8S setup validation
After successful Kubernetes installation on the setup with all the prerequisites mentioned in the section 2.1, check all the pods from the various namespace’s like kube-system, calico and multus on master/worker nodes should be on Running state.

The following snapshots are captured from running setup and can be used for reference for verification.

# 3.1.1.1	K8S nodes

![nodes](https://wwwin-github.cisco.com/storage/user/19835/files/765bb1f0-9166-4577-8193-7a8b71c64d23)

# 3.1.1.2	K8S pods

![pods](https://wwwin-github.cisco.com/storage/user/19835/files/986c3761-95d8-41f8-b822-a8f66238a167)

# 3.1.1.3	K8S all resources

![all](https://wwwin-github.cisco.com/storage/user/19835/files/f6a3ff98-35d5-4e18-a9f6-ac6523d5e081)

# 3.1.1.4	K8S worker node configurations
The following configuration can be referred to validate the worker node.

Network-interface configs:

<img width="513" alt="nw-intf" src="https://wwwin-github.cisco.com/storage/user/19835/files/e237c1d1-72ff-452d-9a29-1a0d8c6b8b3a">

ens160 is node’s management interface and other interfaces (ens192, ens224 and ens256) are used for ASAc.

Huge Page configs:

<img width="510" alt="huge-page" src="https://wwwin-github.cisco.com/storage/user/19835/files/13d9e73f-b2c4-4a3a-8460-942c30e7b0a2">

# 3.1.2	ASA docker image access
ASA docker images are posted in the CCO. Download the ASA docker tar bundle from CCO and load the docker tar image to the host.



         $ docker load < asac9-22-1-1.tar
         $ docker images
         REPOSITORY                                             TAG                                          IMAGE ID
         dockerhub.cisco.com/asac-dev-docker/asac               9.22.1.1                                     55f5dbc5f3aa


After the docker load CLI, the ASA docker image will be available on the host with REPOSITORY as "dockerhub.cisco.com/asac-dev-docker/asac" and TAG as "9.22.1.1".

For kubernetes environment, this image can be pushed to local docker regsirty and the same can be reffered in helm charts.



# 3.1.3	ASAc Deployment 
ASA container can be deployed using helm charts on K8S. The deployment yaml/helm files and helper scripts are stored in this repo. 

Get into “helm” directory and follow the below steps for deployment.

# 3.1.3.1	Update configuration values.
Contents from values.yaml file,

         Default values for asac-helm.
         This is a YAML-formatted file.
         Declare variables to be passed into your templates.
        replicas: 1
        image:
          repository: localhost:5000/asac:9.22.1.1
        persistVolPath: /home/ubuntu/pod-path
        asacMgmtInterface: "ens192"
        asacInsideInterface: "ens224"
        asacOutsideInterface: "ens256"

|Variable Name |	Description
| ------       | ------ |
|repository	| ASA container image path name from local docker registry.
|persistVolPath	| Valid path from worker node where persistent config file will be stored from ASA container.
|asacMgmtInterfcae	| Name of the worker node interface to be used as ASA container management interface.
|asacInsideInterface |	Name of the worker node interface to be used as ASA container inside data interface.
| asacOutsideInterface |	Name of the worker node interface as ASA container outside data interface.

# 3.1.3.2	Update day0 values.
Default Day0 configs are present in the “day0-config” file and User can update this file for specific values as day0 configurations.

# 3.1.3.3	ASAc helm install and uninstall
The helm command to deploy,
helm install <unique-helm-name> <asac-helm-directory-name>

        $ helm install test-asac asac-helm
        NAME: test-asac
        LAST DEPLOYED: Sun Jan 21 07:41:03 2024
        NAMESPACE: default
        STATUS: deployed
        REVISION: 1
        TEST SUITE: None

        $ helm list --all
        NAME            NAMESPACE       REVISION        UPDATED                                 STATUS          CHART           APP VERSION
        test-asac       default         1               2024-01-21 07:41:03.175728953 +0000 UTC deployed        asac-helm-0.1.0 1.16.0     

        $ helm uninstall test-asac
        release "test-asac" uninstalled

# 3.1.3.4	ASAc Validation and Troubleshoot
1.	Status of the helm chart

        ubuntu@k8s-master:~$ helm status test-asac
        NAME: test-asac
        LAST DEPLOYED: Sun Jan 21 07:41:03 2024
        NAMESPACE: default
        STATUS: deployed
        REVISION: 1
        TEST SUITE: None

2.	Status of the ASAc pod

        ubuntu@k8s-master:~$ kubectl get pod
        NAME                    READY   STATUS    RESTARTS   AGE
        asac-5d8c4d547f-6k479   1/1     Running   0          43m
	
3.	ASAc pod events

        LAST SEEN   TYPE     REASON                 OBJECT                            MESSAGE
        52m         Normal   SuccessfulCreate       ReplicaSet/asac-5d8c4d547f        Created pod: asac-5d8c4d547f-6k479
        52m         Normal   ScalingReplicaSet      Deployment/asac                   Scaled up replica set asac-5d8c4d547f to 1
        52m         Normal   WaitForFirstConsumer   PersistentVolumeClaim/local-pvc   waiting for first consumer to be created before binding
        51m         Normal   Scheduled              Pod/asac-5d8c4d547f-6k479         Successfully assigned default/asac-5d8c4d547f-6k479 to k8s-worker
        51m         Normal   AddedInterface         Pod/asac-5d8c4d547f-6k479         Add eth0 [10.244.254.160/32] from k8s-pod-network
        51m         Normal   AddedInterface         Pod/asac-5d8c4d547f-6k479         Add net1 [] from default/macvlan-mgmt-bridge
        51m         Normal   AddedInterface         Pod/asac-5d8c4d547f-6k479         Add net2 [] from default/macvlan-in-bridge
        51m         Normal   AddedInterface         Pod/asac-5d8c4d547f-6k479         Add net3 [] from default/macvlan-out-bridge
        50m         Normal   Created                Pod/asac-5d8c4d547f-6k479         Created container asac
        50m         Normal   Started                Pod/asac-5d8c4d547f-6k479         Started container asac

4.	ASAc pod logs

        ubuntu@k8s-master:~$ kubectl describe pod asac-5d8c4d547f-6k479

5.	ASAc container logs

        ubuntu@k8s-master:~$ kubectl logs asac-5d8c4d547f-6k479

6.	ASAc container access

        ubuntu@k8s-master:~$ kubectl attach -it asac-5d8c4d547f-6k479
        If you don't see a command prompt, try pressing enter.
        ciscoasa> sho
        ciscoasa> show version
        Cisco Adaptive Security Appliance Software Version 9.22(1)1 
        SSP Operating System Version 82.16(0.179i)
        Device Manager Version 7.20(2)10
        Compiled on Thu 02-Nov-23 13:30 GMT by builders
        System image file is "Unknown, monitor mode tftp booted image"
        Config file at boot was "startup-config"
        ciscoasa up 55 mins 53 secs
        Start-up time 12 secs
        Hardware:   ASAc, 2048 MB RAM, CPU Xeon E5 series 2100 MHz, 1 CPU (1 core)
        BIOS Flash Firmware Hub @ 0x0, 0KB
        
         0: Ext: Management0/0       : address is ae15.c291.86b1, irq 0
         1: Ext: GigabitEthernet0/0  : address is faff.65b8.73a9, irq 0
         2: Ext: GigabitEthernet0/1  : address is be89.078a.a560, irq 0
         3: Int: Internal-Data0/0    : address is 0000.0100.0001, irq 0


	
# 3.2	Docker Framework
Kubernetes worker node has all the required configuration to deploy ASA container and can be used as Docker environment to deploy Standalone ASA container.
# 3.2.1 Docker host validation
After successful installation of docker host with all the prerequisite as mentioned in the section 2.2, check the below configuration on the docker host for validation.

# 3.2.1.1	Network interfaces and Huge-Page configurations
Network-interface configs:

<img width="513" alt="nw-intf" src="https://wwwin-github.cisco.com/storage/user/19835/files/1406bbeb-3dea-4c93-8e9b-1bb37b3921e4">

ens160 is node’s management interface and other interfaces (ens192, ens224 and ens256) are used for ASAc.

Huge Page configs:

<img width="510" alt="huge-page" src="https://wwwin-github.cisco.com/storage/user/19835/files/82e8bed7-97f4-4aed-81ce-3e7e0d9ae15b">

# 3.2.2	ASA Docker image access
Refer section 3.1.2 for downloading and creating a ASA docker image locally on docker host from CCO's ASA tar bundle.

The ASA docker image will be available on the host with REPOSITORY as "dockerhub.cisco.com/asac-dev-docker/asac" and TAG as "9.22.1.1". The same repository:tag can be used to deploy ASA container, since this image is available locally on the host.

# 3.2.3	ASAc deployment
ASA container can be deployed using docker cli’s on docker host. There is a helper script is placed in the “standalone-asac” github repo, which invokes the docker cli’s to deploy standalone ASA container. 

Get into “docker” directory and follow the below steps for deployment.

# 3.2.3.1	Docker network creation
Mention the available network interface name from docker host machine while creating a specific docker networks for ASA container. ASA container needs one management interfaces and two data interfaces for inside and outside networks.

Note: When docker starts, these docker networks are attached to docker with alphabetical order on names of docker networks. It is recommended to provide management interface name with name which should resolve to first while ordering alphabetically.

        $ docker network create -d macvlan -o parent=ens192 asac_nw1
        $ docker network create -d macvlan -o parent=ens224 asac_nw2
        $ docker network create -d macvlan -o parent=ens256 asac_nw3

        $ docker network ls
        NETWORK ID     NAME       DRIVER    SCOPE
        06f5320016f8   asac_nw1   macvlan   local
        258954fa5611   asac_nw2   macvlan   local
        3a3cd7254087   asac_nw3   macvlan   local

# 3.2.3.2	Update day0 values
Default Day0 configs are present in the “day0-config” file and User can update this file for specific values as day0 configurations.

# 3.2.3.3	Docker configuration values
There are few configuration vales like CPU, Memory, container-name and image repo name can be configured, and these values are present in the script file “start_docker_asac.sh” itself.

By default values are provided in the script, User can modify these to desired values.

# 3.2.3.4	ASAc docker start and stop
The command to start ASA docker container,
<script-name> <asac-image-path> <asac-mgmt-nw> <asac-data1-nw> <asac-data2-nw>


	

        $ ./start_docker_asac.sh dockerhub.cisco.com/asac-dev-docker/asac:9.22.1.1 asac_nw1 asac_nw2 asac_nw3
        Docker networks are provided..
        Starting ASA Build Container...
        docker create -it --privileged --cap-add=NET_RAW --network asac_nw1 --name asac -e ASAC_CPUS=1 -e ASAC_MEMORY=2048M -v /dev:/dev -v /home/ubuntu/standalone-asac/docker/day0-config:/asac-day0-config/day0-config:Z -v /home/ubuntu/standalone-asac/docker/interface-config:/mnt/disk0/interface-config/interface-config:Z -e CORE_SIZE_LIMIT=200MB -e COREDUMP_PATH=/mnt/coredump_repo/ -e ASA_DOCKER=1 -e ASAC_STANDALONE_MODE=1 -e ASAC_ROOT_PRIVILEGE=1 --entrypoint /asa/bin/lina_launcher.sh dockerhub.cisco.com/asac-dev-docker/asac:9.22.1.1
        
        Mount Points:
        ----------------------------------------------------------------------------------------
        Host                                                       Container
        ----                                                       ---------
        /dev                                                       /dev
        /home/ubuntu/standalone-asac/docker/day0-config       /asac-day0-config/day0-config
        /home/ubuntu/standalone-asac/docker/interface-config  /mnt/disk0/interface-config/interface-config
        ----------------------------------------------------------------------------------------
        
        docker network connect asac_nw2 asac
        docker network connect asac_nw3 asac
        docker start asac

The command to stop/remove ASA docker container,

        $ docker stop asac
        $ docker rm asac

# 3.2.3.5	ASAc Validation and Troubleshoot
	
1.	Status of the ASAc container

        $ docker ps -a
        CONTAINER ID   IMAGE                                                  COMMAND                  CREATED         STATUS         PORTS                                       NAMES
        6e5bff4dbcaf   dockerhub.cisco.com/asac-dev-docker/asac:9.22.1.1      "/asa/bin/lina_launc…"   3 minutes ago   Up 3 minutes                                               asac

2.	ASAc container logs

        $ docker logs asac
        Skip NVMe Device for ASAc mode
        cdrom device /dev/sr0 found
        mount: /mnt/cdrom: WARNING: source write-protected, mounted read-only.
        Error: Encrypted file system support not in Linux kernel.
        nr_overcommit_hugepages set to 128 for virtual platform
        info: ASAc SSHd Directory Created
        No interface-config file found at /interface-config, using default shared file: /mnt/disk0/interface-config/interface-config
        No day0-config file found at /day0-config, using default shared file: /asac-day0-config/day0-config
        info: ASAc Day 0 configuration installed.
        info: ASAc Primay/backup Key installed
        info: Running in vmware virtual environment.
        ....
        INFO: Network Service reload not performed.
        
        INFO: Power-On Self-Test in process.
        .....................................
        INFO: Power-On Self-Test complete.
        INFO: Starting SW-DRBG health test...
        INFO: SW-DRBG health test passed.
        Creating trustpoint "_SmartCallHome_ServerCA" and installing certificate...
        Trustpoint CA certificate accepted.
        Creating trustpoint "_SmartCallHome_ServerCA2" and installing certificate...
        Trustpoint CA certificate accepted.
        User enable_1 logged in to ciscoasa
        Logins over the last 1 days: 1.  
        Failed logins since the last login: 0.  
        Type help or '?' for a list of available commands.
        ciscoasa> 

3.	ASAc container access

        $ docker attach asac
        ciscoasa> en
        ciscoasa> enable 
        Password: *********
        ciscoasa# sh ver
        ciscoasa# sh version 
        Cisco Adaptive Security Appliance Software Version 9.22(1)1 
        SSP Operating System Version 82.16(0.216i)
        Device Manager Version 7.22(1)39
        Compiled on Tue 28-Nov-23 14:37 GMT by builders
        System image file is "Unknown, monitor mode tftp booted image"
        Config file at boot was "startup-config"
        ciscoasa up 9 mins 50 secs
        Start-up time 36 secs
        Hardware:   ASAc, 2048 MB RAM, CPU Xeon E5 series 2100 MHz, 1 CPU (1 core)
        BIOS Flash Firmware Hub @ 0x1, 0KB
        
         0: Ext: Management0/0       : address is 0242.ac12.0002, irq 0
         1: Ext: GigabitEthernet0/0  : address is 0242.ac13.0002, irq 0
         2: Ext: GigabitEthernet0/1  : address is 0242.ac14.0002, irq 0
         3: Int: Internal-Data0/0    : address is 0000.0100.0001, irq 0

