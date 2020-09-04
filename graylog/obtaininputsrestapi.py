#!/usr/bin/env python3

# Graylog Obtain Credentials from Inputs

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import getpass
import globals
import logging
import urllib3
import requests
import colorama

from colorama import Fore
from colorama import Style
from requests.auth import HTTPBasicAuth


colorama.init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# %%%%%%%%%% Functions %%%%%%%%%#


def obtain_inputs(ip, port):

	inputsurl = globals.http + ip + ":" + str(
		port) + "/api/system/inputs?pretty=true"
	graylogpass = getpass.getpass(
		Fore.CYAN + Style.BRIGHT + "[!] Enter Graylog Admin Password: " +
		Style.RESET_ALL)

	try:
		response = requests.get(
			inputsurl, auth=HTTPBasicAuth('admin', graylogpass))

		if response.status_code == 200 and "DOCTYPE html" not in response.text:
			globals.graylog_messages(5)
			data = response.json()
			inputs = data['inputs']

			for x in inputs:
				attributes = x['attributes']

				if ('password' or 'secret') in str(attributes):
					print(globals.SEPARATOR)
					print("[!] " + str(x['title']))
					print(globals.SEPARATOR)
					for y in attributes:
						if ('password' or 'secret') in str(y):
							print(Fore.RED + Style.BRIGHT + "[!] " + str(
								y) + ": " + str(attributes[y]) + Style.RESET_ALL)
						else:
							print("[!] " + str(y) + ": " + str(attributes[y]))
		else:
			globals.graylog_messages(6)

	except Exception as e:
		logging.error(e, exc_info=True)

# %%%%%%%%%% The End %%%%%%%%%%#
