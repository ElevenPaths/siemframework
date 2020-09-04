#!/usr/bin/env python3

# Obtain Splunk System Information

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import sys
import getpass
import globals
import splunklib.client as client

sys.path.append('../')

# %%%%%%%%%%% Functions %%%%%%%%%%%#


def obtain_system_info(ip, port):

	splunk_admin = input("[!] Enter Splunk Admin (Default admin): ")
	splunk_password = getpass.getpass("[!] Enter Splunk Password: ")

	splunk_service = client.connect(
		host=ip, port=port,
		username=splunk_admin, password=splunk_password)
	content = splunk_service.info

	globals.splunk_messages(6)

	for key in sorted(content.keys()):
		value = content[key]
		if isinstance(value, list):
			print("[*] %s:" % key)
			for item in value:
				print("[!]    %s" % item)
		else:
			print("[*] %s: %s" % (key, value))

	globals.splunk_messages(8)
	content = splunk_service.settings.content

	for key in sorted(content.keys()):
		value = content[key]
		print("[*] %s: %s" % (key, value))

# %%%%%%%%%% The End %%%%%%%%%%#
