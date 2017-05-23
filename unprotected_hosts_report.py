import requests, json, os, boto3, time, csv, ast
from base64 import b64decode

### Variables 
AL_CD_URL = "https://publicapi.alertlogic.net/api/tm/v1/protectedhosts"
ENCRYPTED = os.environ['AL_API_KEY']
DECRYPTED_API_KEY = boto3.client('kms').decrypt(CiphertextBlob=b64decode(ENCRYPTED))['Plaintext']
S3BUCKET = os.environ['S3BUCKET']
S3PATH = os.environ['S3PATH']
EC2_INSTANCES = {}
INCLUDE_PROTECTED = ast.literal_eval(os.environ['INCLUDE_PROTECTED'])
WHITELIST_TAGS = str.split(os.environ['WHITELIST_TAGS'],",")
SNSTOPIC = os.environ["SNS_TOPIC"]

def get_cd_protected_hosts(vpc):
	global AL_CD_URL, DECRYPTED_API_KEY
	protected_instnaces = []
	params = {'search': vpc, 'status.status' : 'ok'}
	response = requests.get(AL_CD_URL, params=params, headers={'content-type': 'application/json'}, auth=(DECRYPTED_API_KEY, ''))
	cd_response = response.json()
	for host in cd_response['protectedhosts']:
		protected_instnaces.append(host['protectedhost']['metadata']['ec2_instance_id'])
	return protected_instnaces

def get_all_ec2_instances():
	global EC2_INSTANCES
	try:
		ec2 = boto3.client('ec2', region_name='us-east-1')
	except Exception, e:
		raise("Error getting connecting to EC2 API endpoint in us-east-1: " + e.message)
	try:
		avail_regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
	except Exception, e:
		raise("Error getting region list from EC2: " + e.message)

	for region in avail_regions:
		ec2 = boto3.resource('ec2', region_name=region)
		instances = ec2.instances.filter()
		for instance in instances:
			if EC2_INSTANCES.has_key(instance.vpc_id):
				EC2_INSTANCES[instance.vpc_id].append(instance)
			else:
				EC2_INSTANCES[instance.vpc_id] = []
				EC2_INSTANCES[instance.vpc_id].append(instance)
	return



def process_tags(tags):
	global WHITELIST_TAGS
	whitelist = False
	tag_str = ""
	instance_name = ""
	if tags is None:
		return ""
	for tag in tags:
		if tag["Key"] in WHITELIST_TAGS:
			return True, "", ""
		if tag["Key"] == "Name":
			instance_name = tag["Value"]
		else:
			tag_str +=tag["Key"]+" : " + tag["Value"] + "\n"	
	return False, instance_name, tag_str

def upload_csv_to_s3(filename):
	global S3BUCKET, S3PATH
	s3 = boto3.client('s3')
	try:
		s3.upload_file('/tmp/'+filename, S3BUCKET, S3PATH+filename)
	except Exception, e:
		raise(e)
	try: 
		s3url = s3.generate_presigned_url(ClientMethod='get_object',Params={'Bucket': S3BUCKET,'Key': S3PATH+filename}, ExpiresIn=432000)
	except Exception, e:
		raise('Report was added to S3 bucekt but an error occured in creating S3 URL: ' + e.message)
	return s3url
def publish_sns(s3url, s3url_protected, include_protected, num_unprotected, num_protected):
	global SNSTOPIC
	if include_protected:
		message = 'A new unprotected instances report is available at the URL below, there are ' + str(num_unprotected) + ' instances without Alert Logic agents\n' + s3url + '\n\nThre are ' + str(num_protected) + ' instances with agents, a report of all online and protected instances is available at: ' + s3url_protected + '\n\nNote these links are pre-signed URLs and will expire in 5 days'
	else:
		message = 'A new unprotected instances report is available at the URL below, there are ' + str(num_unprotected) + ' instances without Alert Logic agents\n' + s3url + '\n\nNote this links is a pre-signed URLs and will expire in 5 days'	
	sns_client = boto3.client('sns')
	try:
		response = sns_client.publish(
			TopicArn=SNSTOPIC,
			Message=message,
			Subject='New Unprotected Hosts Report Available in S3'
			)
	except Exception, e:
		raise("Error publishing result to SNS: " + e.message)

def lambda_handler(event, context):
	global EC2_INSTANCES, INCLUDE_PROTECTED
	get_all_ec2_instances()
	cd_hosts_by_vpc = {}
	unprotected_hosts = {}
	protected_hosts = {}
	num_unprotected = 0
	s3url_protected = ""
	for vpc in EC2_INSTANCES.keys():
		cd_hosts_by_vpc[vpc] = get_cd_protected_hosts(vpc)
		for instance in EC2_INSTANCES[vpc]:
			tag_str = ""
			instance_name = ""
			isWhitelisted = False
			if INCLUDE_PROTECTED and instance.tags is not None:
				isWhitelisted, instance_name, tag_str = process_tags(instance.tags)
			if instance.id not in cd_hosts_by_vpc[vpc]:
				if instance.tags is not None and not INCLUDE_PROTECTED:
					isWhitelisted, instance_name, tag_str = process_tags(instance.tags)
				if not isWhitelisted:
					unprotected_hosts[instance.id] = {"Name": instance_name, "instance id" : instance.id, "vpc" : instance.vpc_id, "subnet": instance.subnet_id, "launch": str(instance.launch_time), "tags": tag_str }
			else:
				protected_hosts[instance.id] = {"Name": instance_name, "instance id" : instance.id, "vpc" : instance.vpc_id, "subnet": instance.subnet_id, "launch": str(instance.launch_time), "tags": tag_str }
	filename = "unprotected_hosts_report_" + str(time.gmtime()[0])+str(time.gmtime()[1])+str(time.gmtime()[2])+str(time.gmtime()[3])+str(time.gmtime()[4])+".csv"
	if len(unprotected_hosts) == 0: #all good, no need for repoirt
		return 'All hosts in EC2 are protected'
	with open('/tmp/'+filename, 'w') as f:
		w = csv.DictWriter(f, ["Name","instance id", "vpc", "subnet", "launch", "tags"])
		w.writeheader()
		for u in unprotected_hosts:
			w.writerow(unprotected_hosts[u])
	if INCLUDE_PROTECTED:
		protected_filename = "protected_hosts_report_" + str(time.gmtime()[0])+str(time.gmtime()[1])+str(time.gmtime()[2])+str(time.gmtime()[3])+str(time.gmtime()[4])+".csv"
		with open('/tmp/'+ protected_filename,'w') as f:
			w = csv.DictWriter(f, ["Name","instance id", "vpc", "subnet", "launch", "tags"])
			w.writeheader()
			for p in protected_hosts:
				w.writerow(protected_hosts[p])
		s3url_protected = upload_csv_to_s3(protected_filename)
	s3url = upload_csv_to_s3(filename)
	publish_sns(s3url, s3url_protected, INCLUDE_PROTECTED, len(unprotected_hosts), len(protected_hosts))
	return "Report complete. AWS Account has " + str(len(unprotected_hosts)) + " unprotected hosts and " + str(len(protected_hosts)) + " protected hosts"


