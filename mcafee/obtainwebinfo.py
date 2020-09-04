#!/usr/bin/env python3

# McAfee Login Bruteforce

# %%%%%%%%%%% Libraries %%%%%%%%%%%#


import json
import base64
import globals
import requests
import logging

from colorama import Fore
from colorama import Style

# %%%%%%%%%% Functions %%%%%%%%%#


def mcafee_webinfo(ip, port):
	agents = 'Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/47.0'
	a = 0
	password = input(
		Fore.CYAN + Style.NORMAL + "[!] Enter password of the user Web NGCP: "
		+ Style.RESET_ALL)
	url1 = globals.https + ip + ":" + str(port) + "/ess"
	url2 = globals.https + ip + ":" + str(port) + "/rs/esm/v2/login"
	url3 = globals.https + ip + ":" + str(port) + "/rs/v1/systemInformation"
	headers = {
		'Accept': 'application/json,text/plain,*/*',
		'DNT': '1',
		'Host': ip,
		'Origin': globals.https + ip,
		'Referer': globals.https + ip,
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
	data_show = [
		'callHomeIp', 'releaseNumber', 'hdd',
		'ram', 'processor', 'esssystemTime',
		'statusAndAlertNextCheckIn', 'rulesAndSoftNextCheck', 'backupNextTime'
	]

	try:
		requests.post(
			url1, data='Request=API%13CAC%5FLOGIN%13%14',
			headers=headers, verify=False)
		headers['Accept'] = 'application/json'
		response = requests.post(
			url2, data=json_params, headers=headers, verify=False)
		if response.status_code == 201:
			headers['Cookie'] = response.headers['Set-Cookie']
			headers['X-Xsrf-Token'] = response.headers['xsrf-token']
			response2 = requests.get(url3, headers=headers, verify=False)
			globals.mcafee_messages(1)
			data = json.loads(response2.text)
			for field in data_show:
				if data[field] != "":
					print('[!] ' + field + ':  ' + str(data[field]))
		else:
			globals.messages(10)

	except Exception as e:
		logging.error(e, exc_info=True)

# %%%%%%%%%% The End %%%%%%%%%%#
