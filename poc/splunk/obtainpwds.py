#!/usr/bin/env python3

# Obtain Splunk Stored Credentials

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import colorama
import getpass
import logging
import splunklib.client as client
import sys
from colorama import Fore, Style

sys.path.append('../')

# %%%%%%%%%%% Constants %%%%%%%%%%%#

SEPARATOR = "[*] {0} [*]".format('=' * 110)

# %%%%%%%%%%% Functions %%%%%%%%%%%#

def obtain_credentials(splunkServer):

	print(SEPARATOR)
	splunkAdmin = input("[!] Enter Splunk Admin (Default admin): ")
	splunkPassword = getpass.getpass("[!] Enter Splunk Password: ")

	splunkService = client.connect(host = splunkServer, port = 8089, username = splunkAdmin,
									password = splunkPassword)

	storage_passwords = splunkService.storage_passwords
	print(SEPARATOR)
	print("[!] Currently stored credentials:")
	print(SEPARATOR)

	for credential in storage_passwords:

		if ("``splunk_cred_sep``" in credential.name and "``splunk_cred_sep``" not in
				credential.clear_password):  # new format rest credential

			print("[*] Credential Name: " + credential.name.replace('``splunk_cred_sep``', ''))
			username = credential.username.replace('``splunk_cred_sep``', '')
			username = username[:(len(username) - 1)]
			print("[*] Username: " + Fore.RED + Style.BRIGHT + username)
			print("[*] Encrypted Password: " + credential.encr_password)
			print("[*] Clear Password: " + Fore.RED + Style.BRIGHT + credential.clear_password)
			print(SEPARATOR)

		if "``splunk_cred_sep``" not in credential.name:  # old format credential

			print("[*] Credential Name: " + credential.name)
			print("[*] Username: " + Fore.RED + Style.BRIGHT + credential.username)
			print("[*] Encrypted Password: " + credential.encr_password)
			print("[*] Clear Password: " + Fore.RED + Style.BRIGHT + credential.clear_password)
			print(SEPARATOR)

# %%%%%%%%%% The End %%%%%%%%%%#
