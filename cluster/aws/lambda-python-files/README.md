# lambda-python-files

## cluster_layer.zip 
The cluster_layer.zip can be created on an Amazon Linux VM, with Python 3.9 installed. We recommend
creating an EC2 instance using Amazon Linux 2023 AMI or use AWS Cloudshell, which runs the latest version of Amazon Linux. <br>

For creating the cluster-layer.zip file, you need to first create requirements.txt file that consists of the python library package details and then run the shell script. <br>

(1) Create the requirements.txt file by specifying the python package details. <br>

```bash
$ cat requirements.txt 
pycryptodome
paramiko
requests
scp
jsonschema
cffi
zipp
importlib-metadata
```

(2) Run the following commands to create cluster_layer.zip file. <br>
```bash
$ pip3 install --platform manylinux2014_x86_64 
--target=./python/lib/python3.9/site-packages 
--implementation cp --python-version 3.9 --only-binary=:all: 
--upgrade -r requirements.txt
$ zip -r cluster_layer.zip ./python
```

NOTE: If you encounter a dependency conflict during installation,  such as for packages urllib3 or cryptography, it is recommended that you include the conflicting packages along with their recommended versions in the requirements.txt file. After that, you can run the installation again to resolve the conflict. <br>
(3) The resultant cluster_layer.zip file should be copied to the lambda-python-files folder. <br>

## Lambda Main files 
### lifecycle_asav_cluster.py 

This python file contains lamda_handler for lifecycle-lambda function. 

### configure_asav_cluster.py

This python file contains lamda_handler for Cluster manager lambda function.

## Library Files 

### aws.py 
This file contains classes for various AWS services. <br>

### asav.py
This file contains classes for ASAv methods, SSH connectivity(Paramiko)<br>

## Other files
### constant.py 
This file contains all the constants used in python functions. 

### utility.py
This file contains static python methods used in other python files
