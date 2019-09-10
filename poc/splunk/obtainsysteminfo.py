#!/usr/bin/env python3

# Obtain Splunk System Information

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import getpass
import logging
import splunklib.client as client
import sys

sys.path.append('../')

# %%%%%%%%%%%% Constants %%%%%%%%%%%%%#

SEPARATOR = "[*] {0} [*]".format('=' * 110)

# %%%%%%%%%%% Functions %%%%%%%%%%%#

def obtain_system_info(splunkServer):

	print(SEPARATOR)
	splunkAdmin = input("[!] Enter Splunk Admin (Default admin): ")
	splunkPassword = getpass.getpass("[!] Enter Splunk Password: ")

	splunkService = client.connect(host = splunkServer, port = 8089, username = splunkAdmin,
									password = splunkPassword)
	content = splunkService.info

	print(SEPARATOR)
	print("[!] Splunk Info:")
	print(SEPARATOR)

	for key in sorted(content.keys()):
		value = content[key]
		if isinstance(value, list):
			print("[*] %s:" % key)
			for item in value: print("[!]    %s" % item)
		else:
			print("[*] %s: %s" % (key, value))

	print(SEPARATOR)
	print("[!] Splunk Settings:")
	print(SEPARATOR)

	content = splunkService.settings.content

	for key in sorted(content.keys()):
		value = content[key]
		print("[*] %s: %s" % (key, value))
	print(SEPARATOR)

# %%%%%%%%%% The End %%%%%%%%%%#
