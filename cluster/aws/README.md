# Clustering for the ASAv in a Public Cloud
Clustering lets you group multiple threat defense virtuals together as a single logical device. A cluster provides
all the convenience of a single device (management, integration into a network) while achieving the increased
throughput and redundancy of multiple devices. You can deploy ASA  virtual clusters in a public
cloud using Amazon Web Services (AWS). Only routed firewall mode is supported. <br>

# Prerequisites <br>

## Create "cluster_layer.zip"
The cluster_layer.zip can be created in a Linux environment, such as Ubuntu 18.04 with Python 3.9 installed. <br>

```bash
#!/bin/bash
mkdir -p layer
virtualenv -p /usr/bin/python3.9 ./layer/
source ./layer/bin/activate
pip3 install pycryptodome==3.17.0
pip3 install paramiko==2.11.0
pip3 install requests==2.23.0
pip3 install scp==0.13.2
pip3 install jsonschema==3.2.0
pip3 install cffi==1.15.1
pip3 install zipp==3.1.0
pip3 install importlib-metadata==1.6.0
echo "Copy from ./layer directory to ./python\n"
mkdir -p ./python/
cp -r ./layer/lib/python3.9/site-packages/* ./python/
zip -r cluster_layer.zip ./python
deactivate
```
The resultant cluster_layer.zip file should be copied to the lambda-python-files folder. <br>

## Create "configure_asav_cluster.zip" & "lifecycle_asav_cluster.zip"
A make.py file can be found in the cloned repository top directory. This will Zip the python files into a Zip
file and copy to a target folder. <br>
In order to do these tasks, the Python 3 environment should be available. <br>

Run to create zip files <br>
python3 make.py build <br>

Run to clean <br>
python3 make.py clean <br>

All Zip needs to be uploaded on AWS S3 bucket. <br>

# AWS ASAv Cluster Deployment Steps <br>
## Deploy "infrastructure.yaml"
Go to "CloudFormation" on AWS Console. <br>
1. Click on "Create stack" and select "With new resources(standard)" <br>
2. Select "Upload a template file", Click on "Choose file" and select "infrastructure.yaml" from target folder. <br>
3. Click on "Next", Read all the Parameter's Label & instructions carefully. Add/Update Template parameters according to your requirement. <br>
4. Click "Next" and "Create stack" <br>
5. Once deployment is complete, go to "Outputs" and note S3 "BucketName". <br>
6. Go to S3, Open S3 bucket which is deployed using infra template. Upload "cluster_layer.zip, "configure_asav_cluster.zip" & "lifecycle_asav_cluster.zip".

## Deploy "deploy_asav_clustering.yaml"
Go to "CloudFormation" on AWS Console. <br>
1. Click on "Create stack" and select "With new resources(standard)" <br>
2. Select "Upload a template file", Click on "Choose file" and select "deploy_asav_clustering.yaml" from target folder. <br>
3. Click on "Next", Read all the Parameter's Label & instructions carefully. Add/Update/Select Template parameters according to your requirement. <br>
4. Click "Next" and "Create stack" <br>
5. Lambda functions will configure cluster.
