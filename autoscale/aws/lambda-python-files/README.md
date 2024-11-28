# lambda-python-files

## Steps to create autoscale_layer.zip for Python3.11

A file named *autoscale_layer.zip* needs to be created to provide some essential Python libraries to Lambda functions.This file can be created in a Linux environment, such as Ubuntu 18.04 / 20.04  with Python 3.11 installed.<br>

Run the following commands to create the autoscale_layer.zip <br>

#!/bin/bash <br />
mkdir -p layer <br />
virtualenv -p /usr/local/bin/python3.11 ./layer/ <br />
source ./layer/bin/activate <br />
pip3 install paramiko==2.11.0 <br />
pip3 install requests==2.23.0 <br />
pip3 install scp==0.13.2 <br />
pip3 install jsonschema==3.2.0 <br />
pip3 install cffi==1.15.0 <br />
pip3 install cryptography==2.9.1 <br />
pip3 install zipp==3.1.0 <br />
pip3 install importlib-metadata==1.6.0 <br />
echo "Copy from ./layer directory to ./python\n" <br />
mkdir -p ./python/ <br />
cp -r ./layer/lib/python3.11/site-packages/* ./python/ <br />
zip -r autoscale_layer.zip ./python <br />
deactivate <br />

The resultant autoscale_layer.zip file must be placed in 'lambda-python-files'

## Create "configure_asav.zip" & "lifecycle_asav.zip"
A make.py file can be found in the cloned repository top directory. Running this will Zip the python files into 3 Zip files and copy to a "target" folder. <br>
These 3 Zip files should then be uploaded to S3 Bucket created by infrastructure template.
In order to do these tasks, the Python 3 environment should be available. <br>

Run to create zip files <br>
```
python3 make.py build <br>
```

Run to clean <br>
```
python3 make.py clean <br>
```
### az<1-3>-configuration.txt 
This file is used by Configure ASAv lambda function, which has AZ-specific ASAv routing configuration, and access-list configuration<br>
az1-configuration.txt applies to ASAv devices in az1 (eg: us-east1-a),<br>
az2-configuration.txt applies to ASAv devices in az2 (eg: us-east1-b),<br>
az3-configuration.txt applies to ASAv devices in az3 (eg: us-east1-c) <br>

Uncomment the required lines (remove '!' at start of lines required), these are pushed as CLIs on the ASAv devices.<br>

Sample configuration files are given in the directory "sample-az-configuration-txts". <br>
Refer these sample files based on your topology, and replace the content in az<1-3>-configuration.txt <br>
For deploying GWLB single-arm topology: refer files with 'gwlb-single-arm' prefix. <br>
For deploying GWLB dual-arm topology: refer files with 'gwlb-dual-arm' prefix. <br>
For deploying NLB single-arm topology: refer files with 'nlb' prefix. <br>

## Lambda Main files 

### lifecycle_asav.py 
This python file contains lamda_handler for lifecycle-lambda function. 

### configure_asav.py
This python file contains lamda_handler for Configure ASAv lambda function.


## Library Files 
### aws.py 
This file contains classes for various AWS services. <br>

### asav.py
This file contains classes for ASA methods & SSH connectivity(Paramiko) <br>

## Other files
### constant.py 
This file contains all the constants used in python functions. 

### utility.py
This file contains static python methods used in other python files

