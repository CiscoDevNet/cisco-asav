import os
import time
import paramiko
import json
import socket
import logging
import re

ASAV_SSH_PORT = 22

DEFAULT_PASSWORD = "AsAv_ClU3TeR44"
USE_PUBLIC_IP_FOR_SSH = True
DISABLE_USER_NOTIFY_EMAIL = False


class ASAvInstance():
    """
        This is ASAv class, supposed to instantiated only in Configure_ASAv Lambda function
    """
    def __init__(self, vm_info, id):
        # Get User input, works only for Configure_ASAv Lambda function
        # self.user_input = utl.get_user_input_configure_asav()
        # Inherit CiscoEc2Instance class

        self.public_ip = vm_info['MgmtPublic']
        self.private_ip = vm_info['MgmtPrivate']
        self.port = ASAV_SSH_PORT
        self.username = os.environ.get('ASA_USERNAME')
        self.defaultPassword = DEFAULT_PASSWORD
        self.password = os.environ.get('ASA_PASSWORD')
        self.prev_password = DEFAULT_PASSWORD
        self.new_password = os.environ.get('ASA_PASSWORD')
        self.COMMAND_RAN = 'COMMAND_RAN'
        self.SUCCESS = 'SUCCESS'
        self.FAIL = 'FAILURE'
        self.connection = None
        self.id = id
        self._cached_version = None
        self._cached_vni_prefix = None

    def connect_asa(self):
        """
        Purpose:    This provides object of ParamikoSSH class
        Parameters:
        Returns:    Class object, None
        Raises:
        """
        if USE_PUBLIC_IP_FOR_SSH and self.public_ip is not None:
            # To SSH ASAv Public IP
            ip_to_connect = self.public_ip
        else:
            if self.private_ip is not None:
                # To SSH ASAv Private IP
                ip_to_connect = self.private_ip
            else:
                logging.info("Found None for private_ip of the ASAv instance")
                return None

        connect = ParamikoSSH(ip_to_connect, self.port, self.username, self.password, self.id)
        logging.debug(connect)
        return connect

    # Run an independent command on ASAv
    def run_asav_command(self, command):
        """
        Purpose:    To run a single command
        Parameters: command
        Returns:    'FAILURE', 'COMMAND_RAN'
        Raises:
        """
        output, error = '', ''
        cnt_asa = self.connect_asa()
        try:
            status, output, error = cnt_asa.execute_cmd(command)
        except Exception as e:
            logging.error("Error occurred: {}".format(repr(e)))
            return self.FAIL, output, error
        if status == self.SUCCESS:
            # logging.debug("%s %s %s" % (self.COMMAND_RAN, output, error))
            logging.debug(self.id,"%s %s %s" % (self.COMMAND_RAN, output, error))
            return self.COMMAND_RAN, output, error
        else:
            #logging.warn("Unable to run command output: %s error: %s" % (output, error))
            logging.warn("Unable to run command output: %s error: %s" % (output, error))
            return self.FAIL, output, error

    def get_asav_version(self):
        """
        Purpose:    Get ASAv software version from the device (cached)
        Parameters:
        Returns:    List [major, minor, patch] (e.g., [9, 24, 1]) or None
        Raises:
        """
        # Return cached version if already queried
        if self._cached_version is not None:
            return self._cached_version
        
        try:
            command = "show version | grep Software Version"
            status, output, error = self.run_asav_command(command)
            logging.info("ASAv version output: %s" % output)
            
            if status == self.COMMAND_RAN:
                # Match version with optional build after parenthesis: 9.23(1)22 or 9.20(4.10)
                match = re.search(r'Version\s+([\d.()]+)', output)
                if not match:
                    logging.error("Version not found in output")
                    return None

                version_str = match.group(1)
                # Parse version formats:
                # - 9.24(1) → major=9, minor=24, patch=1, build=0
                # - 9.20(4.10) → major=9, minor=20, patch=4, build=10
                # - 9.23(1)22 → major=9, minor=23, patch=1, build=22
                
                # Extract components using regex
                version_pattern = r'^(\d+)\.(\d+)\((\d+)(?:\.(\d+))?\)(\d+)?$'
                version_match = re.match(version_pattern, version_str)
                
                if not version_match:
                    logging.error("Invalid version format: {}".format(version_str))
                    return None

                try:
                    major = version_match.group(1)
                    # Handle special case where internal builds use 99.x for 9.x
                    if major == '99':
                        major = '9'
                    
                    major_int = int(major)
                    minor_int = int(version_match.group(2))
                    patch_int = int(version_match.group(3))
                    # Build can be in group 4 (inside parens: 9.20(4.10)) or group 5 (after parens: 9.23(1)22)
                    build_int = int(version_match.group(4) or version_match.group(5) or 0)
                    
                    self._cached_version = [major_int, minor_int, patch_int, build_int]
                    
                    # Determine and cache VNI IP prefix based on granular version thresholds
                    self._cached_vni_prefix = self._determine_vni_prefix(self._cached_version)
                    
                    logging.info("Detected ASAv version: {}.{}({}.{}) using VNI IP prefix {}".format(
                        major_int, minor_int, patch_int, build_int, self._cached_vni_prefix))
                    
                    return self._cached_version
                    
                except (ValueError, IndexError, AttributeError) as e:
                    logging.error("Failed to parse version integers from {}: {}".format(version_str, repr(e)))
                    return None
            
            logging.warning("Failed to parse ASAv version from show version output")
            return None
        except Exception as e:
            logging.error("Error getting ASAv version: {}".format(repr(e)))
            return None

    def _determine_vni_prefix(self, version):
        """
        Purpose:    Determine VNI IP prefix based on granular version thresholds
        Parameters: version - List [major, minor, patch, build]
        Returns:    IP prefix string ('169.254.200' or '1.1.1')
        Raises:
        """
        major, minor, patch, build = version
        
        # Define minimum versions for new VNI IP (169.254.200)
        # Format: (major, minor): (major, minor, patch, build)
        thresholds = {
            (9, 20): (9, 20, 4, 10),
            (9, 22): (9, 22, 2, 14),
            (9, 23): (9, 23, 1, 19),
            (9, 24): (9, 24, 1, 0),
        }
        
        # Check if version >= 9.25 (all patches use new IP)
        if (major, minor) >= (9, 25):
            return '169.254.200'
        
        # Check if version >= 10.x (future major versions use new IP)
        if major >= 10:
            return '169.254.200'
        
        # Check specific thresholds for 9.20-9.24
        if (major, minor) in thresholds:
            if tuple(version) >= thresholds[(major, minor)]:
                return '169.254.200'
            else:
                return '1.1.1'
        
        # For minor versions not in threshold list (e.g., 9.21.x)
        # Use conservative approach: default to old IP
        return '1.1.1'

    def _get_vni_ip_prefix(self):
        """
        Purpose:    Determine VNI IP prefix based on software version
        Parameters:
        Returns:    IP prefix string ('169.254.200' for 9.24+, '1.1.1' for older)
        Raises:
        """
        # Return cached VNI prefix if already determined
        if self._cached_vni_prefix is not None:
            return self._cached_vni_prefix
        
        # Trigger version detection (which also caches VNI prefix)
        version = self.get_asav_version()
        
        # If version detection failed, default to 169.254.200
        if self._cached_vni_prefix is None:
            logging.warning("Could not determine version, defaulting to VNI IP prefix 169.254.200")
            self._cached_vni_prefix = '169.254.200'
        
        return self._cached_vni_prefix

    def check_asav_cluster_status(self, cluster_group_name='asav-cluster'):
        '''
        Purpose:
            Check the cluster status of the ASAv Instance
        Arguments:
            * self - ASAv object
        Return:
            * Cluster info
        '''
        command = "show cluster info"
        verify_cluster_not_enabled_string = "Clustering is not "
        verify_cluster_enabled_string = "Cluster {}: On".format(cluster_group_name)
        max_retries = 3
        try:
            for retry in range(0, max_retries):
                if self.verify_string_match(command, verify_cluster_enabled_string) == self.SUCCESS:
                    logging.info("Cluster status : ENABLED")
                    return "ENABLED"
                elif self.verify_string_match(command, verify_cluster_not_enabled_string) == self.SUCCESS:
                    logging.info("Cluster status : NOT ENABLED")
                    return "NOT ENABLED"
                else:
                    return self.FAIL
        except Exception as error:
            logging.error("Exception in check_asav_cluster_status : {}".format(error))
            return self.FAIL

    def apply_cluster_config(self, octet, cluster_group_name='asav-cluster'):
        """
        Purpose:    apply cluster configuration
        Parameters: last octet for management ip address
        Returns:    SUCCESS, FAILURE
        Raises:
        """
        local_unit = "local-unit {}".format(octet)
        cls_group = "cluster group {}".format(cluster_group_name)
        
        # Determine VNI IP based on detected version
        vni_prefix = self._get_vni_ip_prefix()
        
        # Calculate cluster octet with offset for 9.24+
        octet_int = int(octet)
        if vni_prefix == '169.254.200':
            cluster_octet = 192 + (octet_int % 32)
            if not (0 <= cluster_octet <= 255):
                logging.error("Computed cluster IP octet out of range: {}".format(cluster_octet))
                raise ValueError("Computed cluster IP octet out of range: {}".format(cluster_octet))
            netmask = '255.255.255.224'  # /27 for 32-address block (192-223)
        else:
            cluster_octet = octet_int
            netmask = '255.255.255.0'    # /24 for old IP range
        
        cls_int = "cluster-interface vni1 ip {}.{} {}".format(vni_prefix, cluster_octet, netmask)
        
        logging.info("Applying cluster config with VNI IP: {}.{} (mgmt octet: {})".format(vni_prefix, cluster_octet, octet))
        cnt_asa = self.connect_asa()
        write_memory_config = 'copy /noconfirm running-config startup-config'
        expected_outcome_write_memory_config = '#'

        command_set = {
            "cmd": [
                {
                    "command": "enable",
                    "expect": "Password:"
                },
                {
                    "command": self.password,
                    "expect": "#"
                },
                {
                    "command": "configure terminal",
                    "expect": "(config)#"
                },
                {
                    "command": cls_group,
                    "expect":  "#"
                },
                {
                    "command": local_unit,
                    "expect": "#"
                },
                {
                    "command": cls_int,
                    "expect": "#"
                },
                {
                    "command": "priority 1",
                    "expect": "#"
                },
                {
                    "command": "enable noconfirm",
                    "expect": "Local Unit is about to join into cluster"
                },
                {
                    "command": write_memory_config,
                    "expect": expected_outcome_write_memory_config
                }
            ]
        }
        try:
            val = cnt_asa.handle_interactive_session(command_set, self.username, self.password)
        except ValueError as e:
            logging.error("Error occurred in apply_cluster_config: {}".format(repr(e)))
            return self.FAIL
        else:
            return self.SUCCESS

    def enable_password(self):
        """
        Purpose:    To enable password - ASAv
        Parameters:
        Returns:    'FAILURE', 'COMMAND_RAN'
        Raises:
        """
        cnt_asa = self.connect_asa()
        command_set = {
            "cmd": [
                {
                    "command": "enable",
                    "expect": "Password:"
                },
                {
                    "command": self.password,
                    "expect": "#"
                },
                {
                    "command": "conf t",
                    "expect": "(config)#"
                }
            ]
        }

        try:
            cnt_asa.handle_interactive_session(command_set, self.username, self.password)
        except ValueError as e:
            # logging.error("Error occurred: {}".format(repr(e)))
            logging.error("Error occurred: {}".format(repr(e)))
            cnt_asa.close()
            return self.FAIL
        else:
            cnt_asa.close()
            return self.SUCCESS

    def is_passwd_already_set(self):
        """
        Purpose : Check if the enable password is already set or not
        Parameters :
        Return : "SET", "NOT SET"
        """
        cnt_asa = self.connect_asa()
        command = "enable"
        status, output, error = cnt_asa.execute_cmd(command)
        cnt_asa.close()
        if status == "SUCCESS" and "not set" in output:
            return "NOT SET"
        elif status == "SUCCESS":
            return "SET"
        else:
            return self.FAIL


    def set_enable_password(self):
        """
        Purpose:    To enable password - ASAv
        Parameters:
        Returns:    'FAILURE', 'COMMAND_RAN'
        Raises:
        """
        cnt_asa = self.connect_asa()
        # The enable password is not set.  Please set it now.
        # Enter  Password: ************
        # Repeat Password: ************
        write_memory_config = 'copy /noconfirm running-config startup-config'
        expected_outcome_write_memory_config = '#'
        command_set = {
            "cmd": [
                {
                    "command": "enable",
                    "expect": "Enter  Password:"
                },
                {
                    "command": self.password,
                    "expect": "Repeat Password:"
                },
                {
                    "command": self.password,
                    "expect": "#"
                },
                {
                    "command": write_memory_config,
                    "expect": expected_outcome_write_memory_config
                },
                {
                    "command": "configure terminal",
                    "expect": "(config)#"
                },
                {
                    "command": "A",
                    "expect": "#"
                }
            ]
        }

        try:
            cnt_asa.handle_interactive_session(command_set, self.username, self.password)
        except ValueError as e:
            logging.error("Error occurred: {}".format(repr(e)))
            cnt_asa.close()
            return self.FAIL
        else:
            cnt_asa.close()
            return self.SUCCESS


    def check_asav_ssh_status(self):
        """
        Purpose:    To check ASAv SSH is accessible
        Parameters:
        Returns:    SUCCESS, FAILURE
        Raises:
        """
        cnt_asa = self.connect_asa()
        status = cnt_asa.connect(self.username, self.password)
        if status == 'SUCCESS':
            cnt_asa.close()
            return 'SUCCESS'
        elif status == 'Authentication Exception Occurred':
            status = cnt_asa.connect(self.username, self.defaultPassword)
            if status == 'SUCCESS':
                cnt_asa.close()  # As below function triggers interactive shell
                #if self.change_asa_password(cnt_asa, self.defaultPassword, self.password) == 'SUCCESS':
                #    return 'SUCCESS'
                return 'SUCCESS'
            else:
                # logging.error("Unable to authenticate to ASAv instance, please check password!")
                logging.error("Unable to authenticate to ASAv instance, please check password!")
                return 'FAILURE'
        return 'FAILURE'


    # Polling connectivity to ASAv for specified 'minutes'
    def poll_asav_ssh(self, minutes):
        """
        Purpose:    To poll ASAv for SSH accessibility
        Parameters: Minutes
        Returns:    SUCCESS, TIMEOUT
        Raises:
        """
        logging.info("Checking if instance SSH access is available!")
        if minutes <= 1:
            minutes = 2
        for i in range(1, 2 * minutes):
            if i != ((2 * minutes) - 1):
                status = self.check_asav_ssh_status()
                if status != "SUCCESS":
                    # logging.debug(str(i) + " Sleeping for 30 seconds")
                    logging.debug("{} Sleeping for 30 seconds".format(i))
                    time.sleep(1 * 30)
                else:
                    return "SUCCESS"
        # logging.info("Failed to connect to device retrying... ")
        logging.info("Failed to connect to device retrying... ")
        return "TIMEOUT"

    # function to set hostname
    def check_and_configure_hostname(self):
        """
        Purpose:    To configure hostname on ASAv
        Parameters:
        Returns:    'FAILURE', 'COMMAND_RAN'
        Raises:
        """
        hostname = 'asavcluster'
        cnt_asa = self.connect_asa()
        cmd = "hostname {}".format(hostname)
        expected_outcome = "(config)#"
        write_memory_config = 'copy /noconfirm running-config startup-config'
        expected_outcome_write_memory_config = '#'
        command_set = {
            "cmd": [
                {
                    "command": "enable",
                    "expect": "Password:"
                },
                {
                    "command": self.password,
                    "expect": "#"
                },
                {
                    "command": "conf t",
                    "expect": "(config)#"
                },
                {
                    "command": cmd,
                    "expect": expected_outcome
                },
                {
                    "command": write_memory_config,
                    "expect": expected_outcome_write_memory_config
                }
            ]
        }
        try:
            if self.verify_string_match('show hostname', hostname) == "SUCCESS":
                return self.SUCCESS
            cnt_asa.handle_interactive_session(command_set, self.username, self.password)
        except ValueError as e:
            # logging.error("Error occurred: {}".format(repr(e)))
            logging.error("Error occurred: {}".format(repr(e)))
            return self.FAIL
        else:
            return self.SUCCESS

    def get_sn_of_asav(self):
        """
        Purpose:    To get SN of ASAv
        Parameters:
        Returns:    Either SN or N/A
        Raises:
        """
        try:
            command = "show version | include .*[Ss]erial.[Nn]umber:.* " + "\n"
            status, output, error = self.run_asav_command(command)
            output_json = {
                "command": command,
                "status": status,
                "output": output,
                "error": error
            }
            logging.debug(json.dumps(output_json, separators=(',', ':')))
            output = output.replace(" ", "")
            output_list = output.split(":")
            return output_list[1]
        except IndexError as e:
            logging.debug("Error occurred: {}".format(repr(e)))
            logging.error("Unable to get SN of ASAv")
            return 'N/A'
        except Exception as e:
            logging.error("Error occurred: {}".format(repr(e)))
            return 'N/A'

     # function to set password(admin) from prev_password to new_password
    def set_asa_password(self):
        """
        Purpose:    To set password to asa
        Parameters:
        Returns:    SUCCESS, FAILURE
        Raises:
        """
        cnt_asa = self.connect_asa()
        if self.change_asa_password(cnt_asa, self.password, self.new_password) == 'SUCCESS':
            return 'SUCCESS'
        return 'FAILURE'


    # function to change password(admin) from prev_password to new_password
    def change_asa_password(self, cnt_asa, prev_password, new_password):
        """
        Purpose:    To change password from default to user provided
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        cmd1 = 'username ' + self.username + ' password ' + new_password + ' privilege 15'
        cmd2 = 'enable ' + 'password ' + new_password
        write_memory_config = 'copy /noconfirm running-config startup-config'
        expected_outcome_write_memory_config = '#'
        command_set = {
            "cmd": [
                {
                    "command": "enable",
                    "expect": "Password:"
                },
                {
                    "command": prev_password,
                    "expect": "#"
                },
                {
                    "command": "conf t",
                    "expect": "(config)#"
                },
                {
                    "command": cmd1,
                    "expect": "#"
                },
                {
                    "command": cmd2,
                    "expect": "#"
                },
                {
                    "command": write_memory_config,
                    "expect": expected_outcome_write_memory_config
                }
            ]
        }

        try:
            cnt_asa.handle_interactive_session(command_set, self.username, prev_password)
        except ValueError as e:
            logging.error("Error occurred: {}".format(repr(e)))
            return None
        else:
            return 'SUCCESS'
        finally:
            cnt_asa.close()


    def verify_string_match(self, command, verify_string):
        """
        Purpose:    To verify string match
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        cnt_asa = self.connect_asa()
        command_set = {
            "cmd": [
                {
                    "command": "enable",
                    "expect": "Password:"
                },
                {
                    "command": self.password,
                    "expect": "#"
                },
                {
                    "command": "conf t",
                    "expect": "#"
                },
                {
                    "command": command,
                    "expect": verify_string
                }
            ]
        }
        try:
            cnt_asa.handle_interactive_session(command_set, self.username, self.password)
        except ValueError as e:
            logging.error("Error occurred(Value Error): {}".format(repr(e)))
            return self.FAIL
        except Exception as e:
            logging.error("Error occurred(Exception): {}".format(repr(e)))
            return self.FAIL
        else:
            return self.SUCCESS
        finally:
            cnt_asa.close()


    def verify_configuration_file_copy(self, local_file_name):
        """
        Purpose:    To verify whether configuration file copied or not
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        command = 'show disk0: '
        verify_string = local_file_name
        return self.verify_string_match(command, verify_string)


    def verify_asa_license_unregistered(self):
        """
        Purpose:    To verify smart license UNREGISTERED
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        command = 'show license summary'
        verify_string = 'UNREGISTERED'
        return self.verify_string_match(command, verify_string)

    def verify_asa_license_registering(self):
        """
        Purpose:    To verify smart license in REGISTERING state
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        command = 'show license summary'
        verify_string = 'REGISTERING'
        return self.verify_string_match(command, verify_string)

    def verify_asa_license_authorized(self):
        """
        Purpose:    To verify smart license AUTHORIZED
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        command = 'show license features | grep enforce'
        verify_string = 'enforce mode: Authorized'
        return self.verify_string_match(command, verify_string)

    def verify_aws_licensing(self):
        """
        Purpose:    To verify AWS Licensing
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        command = 'show license features | grep License'
        verify_string = 'AWS Licensing'
        return self.verify_string_match(command, verify_string)

    def verify_asav_payg_licensed(self):
        """
        Purpose:    To verify ASAv is Licensed
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        command = 'show license features | grep License'
        verify_string = 'License state: LICENSED'
        return self.verify_string_match(command, verify_string)

    def verify_asav_byol_licensed(self):
        """
        Purpose:    To verify ASAv is Licensed
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        command = 'show license features | grep License'
        verify_string = 'ASAv Platform License State: Licensed'
        return self.verify_string_match(command, verify_string)

    def verify_asa_smart_licensing_enabled(self):
        """
        Purpose:    To verify smart license ENABLED
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        command = 'show license features | grep License'
        verify_string = 'License mode: Smart Licensing'
        return self.verify_string_match(command, verify_string)

    def verify_at_least_one_nat_policy_present(self):
        """
        Purpose:    To verify if at least one NAT policy present
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        command = 'show nat'
        verify_string = 'translate_hits'
        return self.verify_string_match(command, verify_string)

    def poll_asa_license_authorized(self, minutes):
        """
        Purpose:    To poll ASAv for Licensing
        Parameters: Minutes
        Returns:    SUCCESS, TIMEOUT
        Raises:
        """
        logging.info("Checking if instance license is AUTHORIZED")
        if minutes <= 1:
            minutes = 2
        for i in range(1, 2 * minutes):
            if i != ((2 * minutes) - 1):
                status = self.verify_asa_license_authorized()
                if status != "SUCCESS":
                    logging.debug(str(i) + " Sleeping for 15 seconds")
                    time.sleep(1 * 15)
                else:
                    return "SUCCESS"
        return "TIMEOUT"

    # fixme This operation is inconsistent hence NOT SUPPORTED,
    #  Any breakage in Communication, can cause ASAv to be terminated without de-register license.
    def deregister_smart_license(self):
        """
        Purpose:    To deregister smart license
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        cmd1 = 'show license status'
        cmd2 = 'license smart deregister'
        cnt_asa = self.connect_asa()
        write_memory_config = 'copy /noconfirm running-config startup-config'
        expected_outcome_write_memory_config = '#'
        command_set = {
            "cmd": [
                {
                    "command": "enable",
                    "expect": "Password:"
                },
                {
                    "command": self.password,
                    "expect": "#"
                },
                {
                    "command": "conf t",
                    "expect": "#"
                },
                {
                    "command": cmd2,
                    "expect": "#"
                },
                {
                    "command": write_memory_config,
                    "expect": expected_outcome_write_memory_config
                }
            ]
        }
        # logging.info("Initiating de-registration of ASAv with command set: "
        #             + json.dumps(command_set, separators=(',', ':')))
        try:
            cnt_asa.handle_interactive_session(command_set, self.username, self.password)
        except ValueError as e:
            logging.error("Error occurred: {}".format(repr(e)))
            return self.FAIL
        else:
            return self.SUCCESS
        finally:
            cnt_asa.close()

    def run_copy_file_running_config(self, url, file_path):
        """
        Purpose:    To change configure running-config from HTTP/HTTPS
        Parameters: url, s3 bucket/any http server path
        Returns:    SUCCESS, None
        Raises:
        """
        cmd1 = 'copy /noconfirm ' + url + ' ' + file_path
        cmd2 = 'copy /noconfirm ' + file_path + ' running-config'
        write_memory_config = 'copy /noconfirm running-config startup-config'
        expected_outcome_write_memory_config = '#'
        command_set = {
            "cmd": [
                {
                    "command": "enable",
                    "expect": "Password:"
                },
                {
                    "command": self.password,
                    "expect": "#"
                },
                {
                    "command": "conf t",
                    "expect": "#"
                },
                {
                    "command": cmd1,
                    "expect": "#"
                },
                {
                    "command": cmd2,
                    "expect": "#"
                },
                {
                    "command": write_memory_config,
                    "expect": expected_outcome_write_memory_config
                }
            ]
        }
        # Do not print below log, will print password on log
        # logging.info("Initiating configuration of ASAv with command set: "
        #             + json.dumps(command_set, separators=(',', ':')))
        logging.info("Executing commands: " + cmd1)
        logging.info("Executing commands: " + cmd2)
        cnt_asa = self.connect_asa()
        try:
            cnt_asa.handle_interactive_session(command_set, self.username, self.password)
        except ValueError as e:
            logging.error("Error occurred: {}".format(repr(e)))
            return None
        else:
            return 'SUCCESS'
        finally:
            cnt_asa.close()

    def stop_new_connections(self):
        """
        Purpose:    To stop new connections through ASAv
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        cmd1 = 'no ssh 168.63.129.0 255.255.255.0 outside'
        cmd2 = 'no ssh 168.63.129.0 255.255.255.0 inside'
        write_memory_config = 'copy /noconfirm running-config startup-config'
        expected_success_prompt = '#'

        command_set = {
            "cmd": [
                {
                    "command": "enable",
                    "expect": "Password:"
                },
                {
                    "command": self.password,
                    "expect": expected_success_prompt
                },
                {
                    "command": "conf t",
                    "expect": expected_success_prompt
                },
                {
                    "command": cmd1,
                    "expect": expected_success_prompt
                },
                {
                    "command": cmd2,
                    "expect": expected_success_prompt
                },
                {
                    "command": write_memory_config,
                    "expect": expected_success_prompt
                }
            ]
        }
        # logging.info("Initiating de-registration of ASAv with command set: "
        #             + json.dumps(command_set, separators=(',', ':')))
        logging.info("Executing commands: " + cmd1)
        logging.info("Executing commands: " + cmd2)

        cnt_asa = self.connect_asa()
        try:
            cnt_asa.handle_interactive_session(command_set, self.username, self.password)
        except ValueError as e:
            logging.error("Error occurred: {}".format(repr(e)))
            return self.FAIL
        else:
            return self.SUCCESS
        finally:
            cnt_asa.close()



class ParamikoSSH:
    """
        This Python class supposed to handle interactive SSH session
    """
    def __init__(self, server, port=22, username='admin', password=None, id = "1234"):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.port = port
        self.server = server
        self.username = username
        self.password = password
        self.timeout = 30
        self.SUCCESS = 'SUCCESS'
        self.FAIL = 'FAILURE'
        self.AUTH_EXCEPTION = 'Authentication Exception Occurred'
        self.BAD_HOST_KEY_EXCEPTION = 'Bad Key Exception occurred'
        self.SSH_EXCEPTION = 'SSH Exception Occurred'
        self.id = id

    def close(self):
        self.ssh.close()

    def verify_server_ip(self):
        try:
            socket.inet_aton(self.server)
            return self.SUCCESS
        except socket.error as e:
            logging.error("Exception occurred: {}".format(repr(e)))
            return self.FAIL
        except Exception as e:
            logging.error("Exception occurred: {}".format(repr(e)))
            return self.FAIL

    def connect(self, username, password):
        """
        Purpose:    Opens a connection to server
        Returns:    Success or failure, if failure then returns specific error
                    self.SUCCESS = 'SUCCESS'
                    self.FAIL = 'FAILURE'
                    self.AUTH_EXCEPTION = 'Authentication Exception Occurred'
                    self.BAD_HOST_KEY_EXCEPTION = 'Bad Key Exception occurred'
                    self.SSH_EXCEPTION = 'SSH Exception Occurred'
        """
        if self.verify_server_ip() == 'FAILURE':
            return self.FAIL
        try:
            self.ssh.connect(self.server, self.port, username, password, timeout=10)
            logging.debug("Connection to %s on port %s is successful!" % (self.server, self.port))
            return self.SUCCESS
        except paramiko.AuthenticationException as exc:
            logging.warn("Exception occurred: {}".format(repr(exc)))
            return self.AUTH_EXCEPTION
        except paramiko.BadHostKeyException as exc:
            logging.debug("Exception occurred: {}".format(repr(exc)))
            return self.BAD_HOST_KEY_EXCEPTION
        except paramiko.SSHException as exc:
            logging.debug("Exception occurred: {}".format(repr(exc)))
            return self.SSH_EXCEPTION
        except BaseException as exc:
            logging.debug("Exception occurred: {}".format(repr(exc)))
            return self.FAIL

    def execute_cmd(self, command):
        """
        Purpose:    Performs an interactive shell action
        Parameters: Command
        Returns:    action status, output & error
        """
        if self.connect(self.username, self.password) != self.SUCCESS:
            raise ValueError("Unable to connect to server")
        try:
            ssh_stdin, ssh_stdout, ssh_stderr = self.ssh.exec_command(command, timeout=30)
        except paramiko.SSHException as exc:
            logging.error("Exception occurred: {}".format(repr(exc)))
            self.ssh.close()
            return self.FAIL, None, None
        else:
            output = ssh_stdout.readlines()
            error = ssh_stderr.readlines()
            logging.debug('SSH command output: ' + str(output))
            self.ssh.close()
            return self.SUCCESS, str(output), str(error)

    def invoke_interactive_shell(self):
        """
        Purpose:    Performs an interactive shell action
        Parameters:
        Returns:    a new Channel connected to the remote shell
        """
        try:
            shell = self.ssh.invoke_shell()
        except paramiko.SSHException as exc:
            logging.error("Exception occurred: {}".format(repr(exc)))
            self.ssh.close()
            return self.FAIL, None
        else:
            return self.SUCCESS, shell

    def handle_interactive_session(self, command_set, username, password):
        """
        Purpose:    Performs an interactive shell action
        Parameters:
            command_set: a dict of set of commands expressed in command & expect values
            Example:
                {
                  "cmd1": [
                    {
                      "command": "configure password",
                      "expect": "Enter current password:"
                    },
                    {
                      "command": "Cisco123789!",
                      "expect": "Enter new password:"
                    },
                    {
                      "command": "Cisco@123123",
                      "expect": "Confirm new password:"
                    },
                    {
                      "command": "Cisco@123123",
                      "expect": "Password Update successful"
                    }
                  ]
                }
        Returns:
        Raises:
            ValueError based on the error
        """
        if self.connect(username, password) != self.SUCCESS:
            raise ValueError("Unable to connect to server")
        status, shell = self.invoke_interactive_shell()
        if status != self.SUCCESS:
            raise ValueError("Unable to invoke shell")
        if self.send_cmd_and_wait_for_execution(shell, b'\n') is not None:
            for key in command_set:
                set = command_set[key]
                for i in range(0, len(set)):
                    command = (set[i]['command'] + '\n').encode('utf-8')
                    expect = set[i]['expect']
                    if self.send_cmd_and_wait_for_execution(shell, command, expect) is not None:
                        pass
                    else:
                        if password.encode('utf-8') in command:
                            raise ValueError("Unable to pass the Password!")
                        else:
                            raise ValueError("Unable to execute command! : {}".format(command.decode('utf-8')))
        else:
            logging.error("Error in handle_interactive_session")
        return

    def send_cmd_and_wait_for_execution(self, shell, command, wait_string='>'):
        """
        Purpose:    Sends command and waits for string to be received
        Parameters: command, wait_string
        Returns:    rcv_buffer or None
        Raises:
        """
        shell.settimeout(self.timeout)
        total_msg = ""
        try:
            cmd_str = command.decode('utf-8') if isinstance(command, bytes) else str(command)
            logging.info("Sending command: {}".format(cmd_str.strip()))
            shell.send(command)
            while wait_string not in total_msg:
                rcv_buffer = shell.recv(10000)
                total_msg = total_msg + rcv_buffer.decode("utf-8")
                logging.info("Expected string {} in output: {}".format(wait_string, total_msg))

            return total_msg

        except Exception as e:
            logging.error("Error occurred in send_cmd_and_wait_for_execution: {}".format(repr(e)))
            logging.info("ASAv Terminal Output : {}".format(total_msg))
            return None
