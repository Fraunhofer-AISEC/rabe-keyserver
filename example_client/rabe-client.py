#!/usr/bin/env python3
import sys, os
import json, datetime
import requests
import argparse
import time
import zipfile
import pprint
from oauthlib.oauth2 import LegacyApplicationClient
from requests_oauthlib import OAuth2Session
from requests_toolbelt import MultipartEncoder, MultipartEncoderMonitor
import progressbar


# ############### Dependencies ###############
# 	pip3 install requests_oauthlib requests_toolbelt progressbar2
# ############################################

########################################################################

BASE_URL = "http://localhost:8000"

# HTTP Basic Auth
#auth=('admin', 'admin')
auth=None

username = 'admin'
password = 'admin'
#password = password_new
#password = 'FollowthewhiteraBBit!'

session=None
########################################################################

pp = pprint.PrettyPrinter(indent=4, width=160)

def check():
	if sys.version_info.major == 3:
		return True
	else:
		print('Please use Python 3')
		return False

def get_oauth_session():	
	if not "https://" in BASE_URL:
		os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'	# Just for testing, to allow plaintext HTTP

	# OAuth2 token request according to "Resource Owner Password Credentials" flow (RFC 6749)
	client = LegacyApplicationClient(client_id=username)
	oauth = OAuth2Session(client=client)
	token = oauth.fetch_token(token_url=BASE_URL+'/login', username=username, password=password, auth=auth)	
	return oauth

def simple_get_request(call, *params, authorize=False):
	req = "{0}/{1}".format(BASE_URL, call)
	for p in params:
		if p[0] == "?":
			req += p
		else:
			req += "/"+p
	#print("Request: %s" % req)
	
	session = get_oauth_session()

	response = session.get(req, verify=False, auth=auth)
	#pp.pprint(vars(response))

	try:
		# Handle response
		if response.status_code == 401:
			print("Not authorized!")
		elif response.status_code == 200:
			return response.json()
		else:
			print (response.status_code)
			print (response.json())
	except Exception as e:
		print(e)
		pp.pprint(vars(response))

def simple_post_json(call, json, authorize=False):
	req = "{0}/{1}".format(BASE_URL, call)
	
	session = get_oauth_session()

	response = session.post(req, json=json, verify=False, auth=auth)
	#pp.pprint(vars(response))

	try:
		# Handle response
		if response.status_code == 401:
			print("Not authorized!")
		elif response.status_code == 200:
			return response.json()
		else:
			print (response.status_code)
			print (response.json())
	except Exception as e:
		print(e)
		pp.pprint(vars(response))


bar = None
format_custom_text = None
max_filesize = -1
def my_callback(monitor):
	global bar, format_custom_text, max_filesize
	#print(monitor.bytes_read, max_filesize-monitor.bytes_read)
	if bar:
		if monitor.bytes_read < max_filesize:
			format_custom_text.update_mapping(mem=(monitor.bytes_read/1024))
			bar.update(monitor.bytes_read)
		else:
			format_custom_text.update_mapping(mem=(max_filesize/1024))
			bar.update(max_filesize)
			bar.finish()
			bar = None
			print("Waiting for job id")


def version():
	res = simple_get_request('version')
	print(res)

def add_user(username, password):
	json = { "username": username, "password": password }
	simple_post_json("add_user", json)

def main():
	check() or sys.exit(1)
	
	try:
		if len(sys.argv) == 1 or sys.argv[1] in ['help', '-h', '--help']:
			print("Usage: %s <command> <params>" % sys.argv[0])
			print("available commands:")
			print("\t adduser <username> <password>")
		elif sys.argv[1] in ['version']:
			version()
		elif sys.argv[1] in ['adduser']:
			if len(sys.argv) != 4:
				print("wrong syntax. Please use: "+sys.argv[0] + " adduser <username> <password>")
				return
			add_user(sys.argv[2], sys.argv[3])
		else:
			res = simple_get_request(*sys.argv[1:], authorize=True)
			
			if res is not None:
				try:
					pp.pprint(res)
				except IOError:
					pass

	except requests.exceptions.ConnectionError as e:
		print(e)
		print("Server seems to be offline.")

if __name__ == '__main__':
	main()
