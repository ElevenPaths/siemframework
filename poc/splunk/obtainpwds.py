#!/usr/bin/env python3

# Obtain Splunk Stored Credentials

#%%%%%%%%%%% Libraries %%%%%%%%%%%#

import sys
import getpass
sys.path.append('../')
import splunklib.client as client
import colorama
from colorama import Fore, Style

#%%%%%%%%%%% Constants %%%%%%%%%%%#

separator = "[*] ============================================================================================================== [*]"

#%%%%%%%%%%% Functions %%%%%%%%%%%#

def obtaincredentials(splunkServer):

	print(separator)
	splunkAdmin = input("[!] Enter Splunk Admin (Default admin): ")
	splunkPassword = getpass.getpass("[!] Enter Splunk Password: ")

	splunkService = client.connect(host=splunkServer, port=8089, username=splunkAdmin, password=splunkPassword)
	storage_passwords = splunkService.storage_passwords
	print(separator)
	print("[!] Currently stored credentials:")
	print(separator)

	for credential in storage_passwords:
		if ("``splunk_cred_sep``" in credential.name and "``splunk_cred_sep``" not in credential.clear_password): #new format rest credential
			print("[*] Credential Name: " + credential.name.replace('``splunk_cred_sep``',''))
			username = credential.username.replace('``splunk_cred_sep``','')
			username = username[:(len(username)-1)]
			print("[*] Username: "+Fore.RED+Style.BRIGHT+username)
			print("[*] Encrypted Password: " + credential.encr_password)
			print("[*] Clear Password: " + Fore.RED + Style.BRIGHT + credential.clear_password)
			print(separator)

		if("``splunk_cred_sep``" not in credential.name): #old format credential
			print("[*] Credential Name: " + credential.name)
			print("[*] Username: "+Fore.RED+Style.BRIGHT+credential.username)
			print("[*] Encrypted Password: " + credential.encr_password)
			print("[*] Clear Password: "+Fore.RED+Style.BRIGHT+credential.clear_password)
			print(separator)

#%%%%%%%%%% The End %%%%%%%%%%#


