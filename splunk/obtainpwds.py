#!/usr/bin/env python3

# Obtain Splunk Stored Credentials

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import sys
import getpass
import globals
import splunklib.client as client

sys.path.append('../')

# %%%%%%%%%%% Functions %%%%%%%%%%%#


def obtain_credentials(ip, port):

	splunk_admin = input("[!] Enter Splunk Admin (Default admin): ")
	splunk_password = getpass.getpass("[!] Enter Splunk Password: ")

	splunk_service = client.connect(
		host=ip, port=port,
		username=splunk_admin, password=splunk_password)
	cred_sep = "``splunk_cred_sep``"

	storage_passwords = splunk_service.storage_passwords
	globals.splunk_messages(4)

	for credential in storage_passwords:
		# new format rest credential
		if cred_sep in credential.name and cred_sep not in credential.clear_password:

			username = credential.username.replace(cred_sep, '')
			username = username[:(len(username) - 1)]
			mess = [
				credential.name.replace(cred_sep, ''), username,
				credential.encr_password, credential.clear_password]
			globals.splunk_messages(5, mess)

		if cred_sep not in credential.name:  # old format credential
			mess = [
				credential.name, credential.username,
				credential.encr_password, credential.clear_password]
			globals.splunk_messages(5, mess)

# %%%%%%%%%% The End %%%%%%%%%%#
