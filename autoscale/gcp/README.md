# GCP Autoscale Solution:

* Go to gCloud console and set the project:
	* gcloud config set project {your-project-name}
* Have 3 VPC networks, with inside, outside and management. In mgmt VPC network, we need a /28 CIDR for VPC Connector to connect to ASA using Cloud Functions. 
* Create required Firewall Rules and also a Cloud NAT for outside VPC for the Inside application with private ip to connect to the Internet.
* Create a VPC-Connector so that the Cloud Function can login to the ASAv
* Zip the scaleout_action and scalein_function and store them in a Cloud Storage Bucket.
* Create Secret-IDs in Secret Manager with "asav-private-key", "asav-en-password" and "asav-new-password"
* Run pre_deployment.yaml to create all the Google Functions Related Resources.
	* gcloud deployment-manager deployments create pre-deployement --config pre_deployment.yaml
* Run asav_autoscale_params.yaml to create all the resources for the Sandwich Model.
	* gcloud deployment-manager deployments create temp-deployement --config asav_autoscale_params.yaml
* Create required GCP Routes to have traffic flow.

* This ASAv configuration assumes that we have a Linux VM on inside network .
	1. For incoming traffic, by using ELB ip address(external), user can ping the Linux System on inside network.
	2. For outgoing traffic, Linux VM on inside network can ping the internet.(eg. https://www.example.com)
	3. To verify whether the packets are going through the ASAv, one can either capture packets or apply ACLs and check traffic flow.

***Note::Due to load balancer limitation in GCP, "GigabitEthernet0/1" will be used as a Management interface and "Management0/0" will be used as a Data Interface.***

* To generate SSH RSA key-pair, use command:
	* ssh-keygen -t rsa -b 2048

* To delete Deployments:
	* Go to Deployment manager and delete using GUI
	  OR
	* Using gCloud CLI: gcloud deployment-manager deployments delete {deployement-name}
