#!/usr/bin/env python3

# Obtain Splunk Version and Information from Web Interface

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import re
import json
import globals
import urllib3
import logging
import requests

# %%%%%%%%%%%% Constants %%%%%%%%%%%%%#

SEPARATOR = "[*] {0} [*]".format('=' * 110)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# %%%%%%%%%%% Functions %%%%%%%%%%%#


def obtain_splunk_info(ip, port):

	prefix = "http://"
	ssl = 0

	if port == "8443":
		ssl = 1
		prefix = "https://"

	url = prefix + ip + ":" + port

	try:
		if ssl:
			response = requests.get(url, verify=False)
		else:
			response = requests.get(url)

		data = response.text
		json_data = re.findall(r'"content".*?:(.*?)}].*?"generator"', data)
		services_info = json.loads(json_data[0])
		services_session = json.loads(json_data[1])
		config_web = json.loads(json_data[2])
		globals.splunk_messages(6)

		for x in services_info:
			print("[*] " + str(x) + ": " + str(services_info[x]))
		globals.splunk_messages(7)

		for x in services_session:
			print("[*] " + str(x) + ": " + str(services_session[x]))
		globals.splunk_messages(8)

		for x in config_web:
			print("[*] " + str(x) + ": " + str(config_web[x]))

	except Exception as e:
		logging.error(e, exc_info=True)

# %%%%%%%%%% The End %%%%%%%%%%#
