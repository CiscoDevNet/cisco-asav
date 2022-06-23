"""
Copyright (c) 2020 Cisco Systems Inc or its affiliates.

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

Name:       make.py
Purpose:    To build zip files from python files for lambda functions.
            In "target" directory, zip files & template files will be copied.

"""

from __future__ import print_function
import platform
import os
import subprocess
import sys
import shutil

oracle_functions_zip = 'Oracle-Functions.zip'
template1_zip = 'template1.zip'
template2_zip = 'template2.zip'
easy_deploy_zip = 'asav_autoscale_deploy.zip'
full_dir_path = os.path.dirname(os.path.realpath(__file__)) + '/'
target_path = full_dir_path + "target/"

print (target_path)
def print_function_name(function):
    def echo_func(*func_args, **func_kwargs):
        print('Running function: {}'.format(function.__name__))
        return function(*func_args, **func_kwargs)
    return echo_func


def main():
    try:
        print("Argument passed to make.py: {}".format(sys.argv[1]))
    except IndexError as e:
        print(e)
        print("Please use 'clean' or 'build' as argument to make.py")
        print("example: 'python make.py clean'")
    try:
        if sys.argv[1] == 'clean':
            # Cleans the target directory
            clean()
        elif sys.argv[1] == 'build':
            # Cleans the target directory
            clean()
            # Checks if all requirements for build
            setup()
            # Builds in target directory
            build()
            # Create target zip
            easy_deploy_zip_creation()
        else:
            print("No valid argument passed to make! "
                  "Please use clean/build argument.")
    except Exception as e:
        print(e)

    return


@print_function_name
def build():
    # Zips python files for lambda function
    zip_()
    # Copies the files to target directory
    copy()
    return


@print_function_name
def setup():
    print("setup creates target and its sub-directories")
    folder_path = [target_path]
    for path in folder_path:
        try:
            isdir = os.path.isdir(path)
            if isdir:
                pass
            else:
                os.mkdir(path)
        except Exception as e:
            print(e)
    return


@print_function_name
def clean():
    print("clean deletes target directory and contents if exists, further creates empty target directory")
    dir_path = target_path
    print("Cleaning the directory")
    try:
        print("In remove directory")
        shutil.rmtree(dir_path)
    except Exception as e:
        pass

    try:
        isdir = os.path.isdir(dir_path)
        if isdir:
            pass
        else:
            os.mkdir(dir_path)
    except Exception as e:
        print(e)

    return


@print_function_name
def zip_():
    print("Create oracle functions zip file")
    oracle_function_path = full_dir_path + 'oracle_functions/'
    os.chdir(oracle_function_path)
    cmd = 'zip -r ' + target_path + oracle_functions_zip + ' ' + '*'
    print(cmd)
    execute_cmd(cmd)

    template_1_path = full_dir_path + 'templates/tf_template_1/'
    os.chdir(template_1_path)
    cmd = 'zip -r ' + target_path + template1_zip + ' ' + '*'
    print(cmd)
    execute_cmd(cmd)

    template_2_path = full_dir_path + 'templates/tf_template_2/'
    os.chdir(template_2_path)
    cmd = 'zip -r ' + target_path + template2_zip + ' ' + '*'
    print(cmd)
    execute_cmd(cmd)

    return


@print_function_name
def easy_deploy_zip_creation():
    print("Creating easy deploy scripts zip file")
    os.chdir(target_path)
    files_to_be_zipped = "template1.zip template2.zip Oracle-Functions.zip oci_asav_autoscale_deployment.py oci_asav_autoscale_teardown.py deployment_parameters.json teardown_parameters.json"
    cmd = 'zip -r ' + target_path + easy_deploy_zip + ' ' + files_to_be_zipped
    print(cmd)
    execute_cmd(cmd)

    os.remove("oci_asav_autoscale_deployment.py")
    os.remove("oci_asav_autoscale_teardown.py")
    os.remove("deployment_parameters.json")
    os.remove("teardown_parameters.json")
    os.chdir(full_dir_path)
    return


@print_function_name
def copy():
    print("copies contents to target directory")

    print ("Copying cloud shell oracle functions deploy script to target")
    cmd = "cp " + full_dir_path + "deploy_oracle_functions_cloudshell.py" + " " + target_path
    execute_cmd(cmd)

    print("Copying configuration file to target")
    cmd = "cp " + full_dir_path + "asav_configuration.txt" + " " + target_path
    execute_cmd(cmd)

    print("Copying deployment scripts to target")
    cmd = "cp " + full_dir_path + "easy_deploy/oci_asav_autoscale_deployment.py" + " " + target_path
    execute_cmd(cmd)

    cmd = "cp " + full_dir_path + "easy_deploy/deployment_parameters.json" + " " + target_path
    execute_cmd(cmd)

    cmd = "cp " + full_dir_path + "easy_deploy/oci_asav_autoscale_teardown.py" + " " + target_path
    execute_cmd(cmd)

    cmd = "cp " + full_dir_path + "easy_deploy/teardown_parameters.json" + " " + target_path
    execute_cmd(cmd)

    return


def execute_cmd(cmd):
    # print(cmd)
    subprocess.call(cmd, shell=True)


if __name__ == '__main__':
    if platform.system() == 'Darwin' or platform.system() == 'Linux':
        main()
    else:
        print("Un-supported platform: %s" % platform.system())
        print("Supported platforms: Darwin, Linux")
