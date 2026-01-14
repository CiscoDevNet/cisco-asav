# Clustering for the ASAv in a Public Cloud
Clustering lets you group multiple ASA Virtuals together as a single logical device. A cluster provides
all the convenience of a single device (management, integration into a network) while achieving the increased
throughput and redundancy of multiple devices. You can deploy ASA Virtual Clusters in a public
cloud using Amazon Web Services (AWS). Only routed firewall mode is supported. <br>
From release 9.22 onwards, Cluster deployment in multiple availability zones is supported.

# Prerequisites <br>

## Git Clone repository
Clone the repository 'cisco-asav' to your local environment. Navigate to - cisco-asav/cluster/aws for the required content

## Create "cluster_layer.zip"
The cluster_layer.zip can be created on an Amazon Linux VM, after installing Python 3.13 on it. We recommend creating an AmazonLinux-2023 EC2 Instance or using AWS Cloudshell, which runs the latest version of Amazon Linux. <br>

**Steps to prepare the environment (if not already done):**
*   Install `git`:
    ```bash
    sudo yum install git -y
    ```
*   Install and initialize `pyenv`:
    ```bash
    curl https://pyenv.run | bash
    echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
    echo '[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
    echo 'eval "$(pyenv init -)"' >> ~/.bashrc
    echo 'eval "$(pyenv virtualenv-init -)"' >> ~/.bashrc
    source ~/.bashrc
    ```
*   Install development tools and libraries required for Python compilation:
    ```bash
    sudo yum groupinstall -y "Development Tools"
    sudo yum install -y gcc openssl-devel bzip2-devel libffi-devel zlib-devel readline-devel sqlite-devel wget make
    ```
*   Install Python 3.13.5 using `pyenv` and set it as global:
    ```bash
    pyenv install 3.13.5
    pyenv global 3.13.5
    pyenv rehash
    ```

**Steps to create `cluster_layer.zip`:**
*   Create and activate a Python 3.13 virtual environment:
    ```bash
    python3.13 -m venv myenv
    source myenv/bin/activate
    ```
*   Create file `requirements.txt` listing the required packages:
    ```
    cat > requirements.txt << EOF
    pycryptodome
    paramiko
    requests
    scp
    jsonschema
    cffi
    zipp
    importlib-metadata
    EOF
    ```
*   Install them using the following command:
    ```bash
    pip3 install --platform manylinux2014_x86_64 --target=./python/lib/python3.13/site-packages --implementation cp --python-version 3.13 --only-binary=:all: --upgrade -r requirements.txt
    ```
*   Copy to`cluster_layer.zip` file:
    ```bash
    zip -r cluster_layer.zip ./python
    ```
*   Deactivate the virtual environment.

The resultant `cluster_layer.zip` file should be copied to the `lambda-python-files` folder.

## Create "configure_asav_cluster.zip" & "lifecycle_asav_cluster.zip"
A make.py file can be found in the cloned repository top directory. Running this will Zip the python files into Zip
files and copy to a "target" folder. <br>
In order to do these tasks, the Python3 environment should be available. <br>

Run to create zip files <br>
```bash
python3 make.py build <br>
```

Run to clean (only if you face errors)<br>
```bash
python3 make.py clean <br>
```

All 3 Zip files need to be uploaded to AWS S3 bucket in a further step. <br>

# AWS ASAv Cluster Deployment Steps <br>
## Deploy "infrastructure.yaml"
Go to "CloudFormation" on AWS Console. <br>
1. Click on "Create stack" and select "With new resources(standard)" <br>
2. Select "Upload a template file", Click on "Choose file" and select "infrastructure.yaml" from target folder. <br>
3. Click on "Next", Read all the Parameter's Label & instructions carefully. Add/Update Template parameters according to your requirement. <br>
4. Click "Next" and "Create stack" <br>
5. Once deployment is complete, go to "Outputs" and note S3 "BucketName". <br>
6. Go to S3, Open S3 bucket which is deployed using infra template. Upload previously-created "cluster_layer.zip, "configure_asav_cluster.zip" & "lifecycle_asav_cluster.zip" to the S3 Bucket

## Deploy "deploy_asav_clustering.yaml"
Go to "CloudFormation" on AWS Console. <br>
1. Click on "Create stack" and select "With new resources(standard)" <br>
2. Select "Upload a template file", Click on "Choose file" and select "deploy_asav_clustering.yaml" from target folder. <br>
3. Click on "Next", Read all the Parameter's Label & instructions carefully. Add/Update/Select Template parameters according to your requirement. <br>
4. Click "Next" and "Create stack" <br>
5. Lambda functions will configure cluster.
