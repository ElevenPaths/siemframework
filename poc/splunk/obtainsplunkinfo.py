#!/usr/bin/env python3

# Obtain Splunk Version and Information from Web Interface

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import json
import logging
import re
import requests
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# %%%%%%%%%%%% Constants %%%%%%%%%%%%%#

SEPARATOR = "[*] {0} [*]".format('=' * 110)

# %%%%%%%%%%% Functions %%%%%%%%%%%#

def obtain_splunk_info(splunkServer):

	splunkPort = input("[!] Enter Splunk Web Interface Port Number (Default Value 8000): ")
	prefix = "http://"
	ssl = 0

	if splunkPort == "8443":

		ssl = 1
		prefix = "https://"
		requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

	url = prefix + splunkServer + ":" + splunkPort

	try:
		if ssl:
			response = requests.get(url, verify = False)
		else:
			response = requests.get(url)

		data = response.text
		jsondata = re.findall(r'"content".*?:(.*?)}].*?"generator"', data)
		services_info = json.loads(jsondata[0])
		services_session = json.loads(jsondata[1])
		config_web = json.loads(jsondata[2])

		print(SEPARATOR)
		print("[!] Splunk Server Information")
		print(SEPARATOR)

		for x in services_info:
			print("[*] " + str(x) + ": " + str(services_info[x]))
		print(SEPARATOR)
		print("[!] Splunk Session Information")
		print(SEPARATOR)

		for x in services_session:
			print("[*] " + str(x) + ": " + str(services_session[x]))
		print(SEPARATOR)
		print("[!] Splunk Config Web")
		print(SEPARATOR)

		for x in config_web:
			print("[*] " + str(x) + ": " + str(config_web[x]))
		print(SEPARATOR)

	except Exception as e:
		logging.error(e, exc_info = True)

# %%%%%%%%%% The End %%%%%%%%%%#
