#!/usr/bin/env python3
##########################################################################
#
#	Example client for the r-ABE attribute based encryption REST service
#
#
#   ############### Dependencies ###############
#   	pip3 install requests_oauthlib requests_toolbelt
#   ############################################
#
#
#	Use as follows:
#
#   # setting up a new scheme of type "bsw". Attributes assigned to the user are space-separated
#   $python3 ./rabe-client.py scheme_setup bsw TEST1 TEST2 
#   11984071560866280529
#   
#   # The returned value is your session_id for that scheme
#
#   # Encrypt the string "test" for attribute TEST1 and store result in an env variable:
#   $CIPHER=`python3 ./rabe-client.py encrypt test "{\"OR\": [{\"ATT\": \"attribute_1\"}, {\"ATT\": \"attribute_2\"}]}" 11984071560866280529`
#
#   # Decrypt the string "test" for attributes TEST1 and TEST2:
#   $python3 ./rabe-client.py decrypt "$CIPHER" 8777877240608612071
#
#
##########################################################################

import sys
import os
import json
import datetime
import requests
import argparse
import time
import zipfile
import pprint
from oauthlib.oauth2 import LegacyApplicationClient
from requests_oauthlib import OAuth2Session
from requests_toolbelt import MultipartEncoder, MultipartEncoderMonitor
import progressbar



########################################################################

BASE_URL = "http://localhost:8000"

username = 'admin'
password = 'admin'

session=None
########################################################################

pp = pprint.PrettyPrinter(indent=4, width=160)


def check():
	if sys.version_info.major == 3:
		return True
	else:
		print('Please use Python 3')
		return False


# Unused at the moment
#def get_oauth_session():
	#if "https://" not in BASE_URL:
		#os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' 	# Just for testing, to allow plaintext HTTP
#
	## OAuth2 token request according to "Resource Owner Password Credentials" flow (RFC 6749)
	#client = LegacyApplicationClient(client_id=username)
	#oauth = OAuth2Session(client=client)
	#token = oauth.fetch_token(token_url=BASE_URL + '/login', username=username, password=password, auth=auth)
	#return oauth


def simple_get_request(call, *params, authorize=False):
	req = "{0}/{1}".format(BASE_URL, call)
	for p in params:
		if p[0] == "?":
			req += p
		else:
			req += "/" + p
	#session = get_oauth_session()
	session = requests.Session()

	response = session.get(req, verify=False)

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


def simple_post_json(call, data, authorize=False):
	req = "{0}/{1}".format(BASE_URL, call)
	#session = get_oauth_session()
	session = requests.Session()
	response = session.post(req, json=data, verify=False)

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


def add_user(username, password, session_id, attributes):
	req = "{0}/add_user".format(BASE_URL)
	data = {
		"username": username, 
		"password": password,
		"random_session_id": session_id,
		"attributes": attributes
	}
	requests.post(req, json=data)


def scheme_setup(scheme, json_attributes):
	data = {"scheme": scheme, "attributes": json_attributes}
	print(simple_post_json("setup", data))


def public_key():
	print(simple_get_request("pk"))


def encrypt(plaintext, policy, session_id):
	data = {"plaintext": plaintext, "policy": policy, "session_id": session_id}
	print(simple_post_json("encrypt", data))


def decrypt(ciphertext, session_id):
	data = {"ct": ciphertext, "session_id": session_id, "username": username, "password": password}
	print(simple_post_json("decrypt", data))


def main():
	check() or sys.exit(1)

	try:
		if len(sys.argv) == 1 or sys.argv[1] in ['help', '-h', '--help']:
			print("Usage: %s <command> <params>" % sys.argv[0])
			print("available commands:")
			print("\t adduser <username> <password> <session_id> <attributes>")
			print("\t scheme_setup <scheme> <attributes>")
			print("\t public_key <session_id>")
			print("\t encrypt <plaintext> <policy> <session_id>")
			print("\t decrypt <ciphertext> <session_id>")
		elif sys.argv[1] in ['version']:
			version()
		elif sys.argv[1] in ['adduser']:
			if len(sys.argv) < 5:
				print("wrong syntax. Please use: " + sys.argv[0] + " adduser <username> <password> <session_id> [attr_1], [attr_2], ...")
				return
			add_user(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:])
		elif sys.argv[1] in ['scheme_setup']:
			if len(sys.argv) < 4:
				print("wrong syntax. Please use: " + sys.argv[0] + " scheme_setup <scheme> [attr_1], [attr_2] , ...")
				return
			scheme_setup(sys.argv[2], sys.argv[3:])
		elif sys.argv[1] in ['public_key']:
			if len(sys.argv) != 3:
				print("wrong syntax. Please use: " + sys.argv[0] + " public_key <session_id>")
				return
			public_key()
		elif sys.argv[1] in ['encrypt']:
			if len(sys.argv) != 5:
				print("wrong syntax. Please use: " + sys.argv[0] + " encrypt <plaintext> <policy> <session_id>")
				return
			encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
		elif sys.argv[1] in ['decrypt']:
			if len(sys.argv) != 4:
				print("wrong syntax. Please use: " + sys.argv[0] + " decrypt <ciphertext> <session_id>")
				return
			decrypt(sys.argv[2], sys.argv[3])
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
