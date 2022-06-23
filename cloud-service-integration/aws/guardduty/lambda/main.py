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

Name:       main.py
Purpose:    This python file has handler for guardduty event analyser lambda
"""

import os
import json
import utils as util
import aws as aws_util
from asav import ASAv
from concurrent import futures

# Setup Logging
logger = util.setup_logging(os.environ['DEBUG_LOGS'])

# Get User input
user_input = util.get_user_input_gd_event_analyser_lambda()
obj_group_cmd = ['object-group network {group_name}', 'network-object host {malicious_ip}']

def lambda_handler(event, context):
	"""
	Purpose:    Finding Analyser Lambda, to analyse GuardDuty finding and configure network object group in ASAv's
	Parameters: AWS Events(CloudWatch)
	Returns:
	Raises:
	"""

	if user_input is None:
		return
	user_input['default_object_group'] = 'aws-gd-suspicious-hosts'
	user_input['email_subject'] = 'GuardDuty Event Notification - [{}]'.format(user_input['deployment_name'])

	util.put_line_in_log('Lambda Handler started', 'thick')
	logger.debug('Received Lambda Event: ' + json.dumps(event, separators=(',', ':')))

	try:
		eventSource = util.fetch_object(event, 'detail/service/serviceName')
		if eventSource == 'guardduty':
			event_detail = util.fetch_object(event, 'detail')
			logger.debug('Received an event of type {}' .format(eventSource))
			take_action(event_detail)
		else:
			logger.info('Skipping event as this is not a guardduty event')
	except util.NotifyWithError as e:
		logger.error(e)
		send_notification(user_input['email_subject'], e.message)
		return
	except Exception as e:
		logger.error('Failed to process event, Error - {}'.format(e))
		return

	util.put_line_in_log('Lambda Handler finshed', 'thick')
	return {'statusCode': 200, 'body': 'Lambda execution successful'}

def take_action(event):
	"""
	Purpose:    This function will parse the event and based on the analysis,
				it takes the required action
	Parameters: event detail
	Returns:
	Raises:
	"""
	try:
		severity = util.fetch_object(event, 'severity')
		logger.info('Recieved a guardduty event with severity level {}' .format(float(severity)))
		if float(severity) >= float(user_input['min_severity']):
			malicious_ip = util.fetch_object(event, 'service/action/networkConnectionAction/remoteIpDetails/ipAddressV4')
			direction = util.fetch_object(event, 'service/action/networkConnectionAction/connectionDirection')
			threatlist = util.fetch_object(event, 'service/additionalInfo/threatListName')
			finding_id = util.fetch_object(event, 'id')
			finding_type = util.fetch_object(event, 'type')
			if malicious_ip is None or direction == 'OUTBOUND' or direction == 'UNKNOWN' and threatlist is None:
				logger.info('Malicious IP: {}, connection direction: {}, threatlist: {}'.format(malicious_ip, direction,
																								threatlist))
				logger.info('No Action required for finding - {}, finding type - {}' .format(finding_id, finding_type))
				return
		else:
			logger.info('Skipping the finding as the severity {} is lower than configured level {}'.format(float(severity), float(user_input['min_severity'])))
			return
	except Exception as e:
		raise Exception('Unable to parse event attributes, {}'.format(e))
		
	logger.info('Processing the event with finding id - {}, finding type - {}' .format(finding_id, finding_type))
	logger.info('Successfully parsed the event with malicious IP: {}, connection direction: {}, threatlist: {}'.format(malicious_ip, direction, threatlist))

	try:
		# update blacklist file in S3
		logger.debug('Updating the malicious host details in the S3 report')
		is_new = update_blacklist(malicious_ip)
		if not is_new:
			logger.info('Skipping finding id {} with ip address {}, item has been already processed earlier' .format(finding_id, malicious_ip))
			return
	except Exception as e:
		logger.error('Error while updating the malicious host in the S3 report: {}'.format(e))
		raise Exception('Unable to perform S3 operations, {}'.format(e))
	logger.info('Successfully updated the malicious host in the S3 report')

	asav_details = []
	message = 'Hello,\n\nAWS GuardDuty has reported the finding \"{finding_type}\" with remote IP(malicious IP) {malicious_ip}.\nThe remote IP(malicious IP) is updated in the report file in S3 bucket\n\tReport file s3 URI - {s3_url}\n\tReport file object URL - {web_url}\n'.format(finding_type=finding_type, malicious_ip=malicious_ip, s3_url=aws_util.get_s3_url(user_input['s3_bucket'], user_input['s3_report_key']), web_url=aws_util.get_object_url(user_input['s3_bucket'], user_input['s3_report_key']).split('?')[0])
	logger.info('Fetching ASAv details from the provided configuration file {}'.format(user_input['asav_input_file']))
	try:
		resp = aws_util.get_object(user_input['s3_bucket'], user_input['asav_input_file'])
		asav_data = resp['Body'].read().decode('utf-8')
	except Exception as e:
		message += '\nASAv details is missing.\nYou may add the malicious host {} to the network object group and configure an access control block rule on your ASAv.\n'.format(malicious_ip)
		raise util.NotifyWithError('Unable to get ASAv details, {}'.format(e), message)
	
	asav_entities = []
	try:
		# Parse ASAv details
		asav_details = util.parse_config(asav_data)
		logger.info('Successfully parsed ASAv config file, generating the network object group commands to be applied')
		
		asav_details = validate_asav_input(asav_details, malicious_ip)
		if len(asav_details) == 0:
			raise Exception('No ASAv details found in ASAv input file')
		logger.debug('Successfully parsed ASAv details, adding malicious host to the network object group')
		
		# Using threads for running concurrent tasks
		ex_pool = futures.ThreadPoolExecutor(max_workers=3)
		results = ex_pool.map(asav_send_cmd, iter([x for x in asav_details if 'Valid' not in x]))
		
		# Collect execution results
		for res in list(results):
			if res['Status']:
				logger.info('Successfully updated the object group(s) {} for ASAv {}'.format(', '.join(res['object-group-name']), res['public-ip']))
				msg = 'Object group(s) \"{}\" updated'.format(', '.join(res['object-group-name']))
				if res['object-group-name'][0] == user_input['default_object_group']:
					msg = 'Object group name is not provided, updated default object group \"{}\"'.format(res['object-group-name'][0])
				asav_entities.append([res['name'], res['public-ip'], 'Success', msg])
			else:
				logger.error('Failed to update the object group(s) {} for ASAv {}, {}'.format(', '.join(res['object-group-name']), res['public-ip'], res['error']))
				asav_entities.append([res['name'], res['public-ip'], 'Failure', 'Object group(s) \"{}\" could not be updated, {}'.format(', '.join(res['object-group-name']), res['error'])])
	except Exception as e:
		message += '\nPlease provide valid ASAv details in the ASAv configuration file {}.\nYou may add the malicious host {} to the network object group and configure an access control policy/rule using the network object group on the ASAv(s) to block the malicious host reported.\n'.format(user_input['asav_input_file'], malicious_ip)
		raise util.NotifyWithError('Unable to send commands to ASAv, {}'.format(e), message)
	
	message += '\nBelow is the status of network object updates(with malicious host) on the ASAv(s) provided in the configuration:\n\n'
	# Collect invalid ASAv entries
	for entry in asav_details:
		if 'Valid' in entry and not entry['Valid']:
			asav_entities.append([entry['name'], entry['public-ip'], 'Failure', entry['error']])
	
	# Build notification message from the result
	if len(asav_entities) > 0:
		message += util.print_table(["ASAv ID", "ASAv IP", "Update Status", "Remarks"], asav_entities)
		
	message += '\n\nYou may add an access control policy/rule using the network object group on the ASAv(s) to block the malicious host {} reported.(ignore if already configured)' .format(malicious_ip)
	message += '\nYou may also fix the errors(if any) causing the update failures.(Please check the AWS CloudWatch logs for more details about the failure)\nFor the failed updates, please add the malicious IP to the network object manually.'
	send_notification(user_input['email_subject'], message)
	logger.info('Successfully published notification for the guardduty event')
		
def send_notification(subject, message):
	"""
	Purpose:    This function will send email notification to subscribed endpoints
	Parameters: email subject and message
	Returns:
	Raises: Exception when publish to SNS fails
	"""
	logger.info('Publishing Message: ' + json.dumps(message))
	try:
		aws_util.publish_to_topic(user_input['sns_topic_arn'], subject, message)
	except Exception as e:
		raise Exception('Unable to publish message to SNS Topic, {}'.format(e))

def update_blacklist(ip_address):
	"""
	Purpose:    This function will update the malicious host to the file in S3
	Parameters: ip address
	Returns: True if new finding, False otherwise
	Raises: exception if it fails to fetch/read/update blacklist
	"""
	# Write malicious IP to S3
	key = user_input['s3_report_key']
	acl_key = user_input['s3_report_key']
	obj_acl = None
	try:
		aws_util.head_bucket(user_input['s3_bucket'])
	except Exception as e:
		raise Exception('Failed to get S3 bucket to store blacklist, {}'.format(e))

	try:
		aws_util.head_object(user_input['s3_bucket'], key)
		try:
			resp = aws_util.get_object(user_input['s3_bucket'], key)
			blacklist_data = resp['Body'].read().decode('utf-8')
		except Exception as e:
			raise Exception('Failed to get blacklist file content from S3, {}'.format(e))
			return

	except Exception as e:
		logger.debug('Blacklist file does not exist')
		blacklist_data = ''
		acl_key = user_input['s3_base_path']

	try:
		obj_acl = aws_util.get_object_acl(user_input['s3_bucket'], acl_key)
	except Exception as e:
		logger.error('Failed to get blacklist file permissions from  S3, {}'.format(e))

	if len(blacklist_data) > 0 and not blacklist_data.endswith('\n'):
		blacklist_data += '\r\n'
	ip_addr_str = ip_address + '\r\n'
	is_new_finding = False
	if ip_addr_str not in blacklist_data:
		blacklist_data = blacklist_data + ip_addr_str
		is_new_finding = True

	try:
		aws_util.put_object(user_input['s3_bucket'], key, blacklist_data)
	except Exception as e:
		raise Exception('Failed to save blacklist file in S3, {}'.format(e))

	if obj_acl is not None:
		try:
			aws_util.put_object_acl(user_input['s3_bucket'], key, {
				'Grants': obj_acl['Grants'],
				'Owner': obj_acl['Owner']},
			)
		except Exception as e:
			logger.error('Failed to update blacklist file permissions in S3, {}'.format(e))

	return is_new_finding

def validate_asav_input(asav_details, malicious_ip):
	"""
	Purpose:    This function will validate asav input file and generate the required CLIs
	Parameters: asav details object and malicious IP
	Returns: validated asav details object
	Raises:
	"""
	mandatory_fields = ['public-ip', 'username', 'password', 'enable-password']
	for i in range(0, len(asav_details)):
		if all(item in asav_details[i].keys() for item in mandatory_fields):
			if 'object-group-name' not in asav_details[i] or len(asav_details[i]['object-group-name'].strip()) == 0:
				logger.info('ASAv network object group is not provided at section {} in asav details input file, configuring default name as \"{}\"' .format(asav_details[i]['name'], user_input['default_object_group']))
				asav_details[i]['object-group-name'] = [user_input['default_object_group']]
			else:
				asav_details[i]['object-group-name'] = [x.strip() for x in asav_details[i]['object-group-name'].split(',') if len(x.strip()) > 0]
			commands = []
			for object_grp in asav_details[i]['object-group-name']:
				for cmd in obj_group_cmd:
					commands.append(cmd.format(group_name=object_grp, malicious_ip=malicious_ip))
			asav_details[i]['commands'] = commands
			if user_input['kms_arn'] is not None:
				try:
					asav_details[i]['password'] = aws_util.get_decrypted_key(asav_details[i]['password'])
					asav_details[i]['enable-password'] = aws_util.get_decrypted_key(asav_details[i]['enable-password'])
				except Exception as e:
					logger.error('Failed to decrypt password for the ASAv details provided at section {} in the ASAv details file {}, skipping this entry, cannot add the malicious host to the network object group for this ASAv.'.format(asav_details[i]['name'], user_input['asav_input_file']))
					asav_details[i]['Valid'] = False
					asav_details[i]['error'] = 'Failed to decrypt password/enable-password provided at section {}'.format(asav_details[i]['name'])
		else:
			logger.error('Incomplete ASAv details at section {} in the ASAv details file {}, skipping this entry, cannot add the malicious host to the network object group for this ASAv.' .format(asav_details[i]['name'], user_input['asav_input_file']))
			if 'public-ip' in asav_details[i]:
				asav_details[i]['Valid'] = False
				asav_details[i]['error'] = 'One or more ASAv input details missing at section {}'.format(asav_details[i]['name'])
	return asav_details

def asav_send_cmd(asav_details):
	"""
	Purpose:    This function initialises ASAv class and
				calls to method to configure CLI in ASAv
	Parameters: asav details object
	Returns: updated asav details object
	Raises:
	"""
	try:
		asav = ASAv(
			asav_details['public-ip'],
			asav_details['username'],
			asav_details['password'],
			asav_details['enable-password'])
		res = asav.exec_asav_command(asav_details['commands'])
		if res == True:
			asav_details['Status'] = True
		else:
			asav_details['Status'] = False
			asav_details['error'] = res

	except Exception as e:
		logger.error('Failed to send the CLIs to ASAv - {}, Error - {}'.format(asav_details['public-ip'], e))
	return asav_details
