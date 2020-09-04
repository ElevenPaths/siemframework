#!/usr/bin/env python3

# OSSIM Obtain Configuration Information

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import re
import base64
import pandas
import urllib3
import globals
import getpass
import logging
import requests

from colorama import Fore, Style
from colorama import init

init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# %%%%%%%%%% Functions %%%%%%%%%#


def ossim_config(ip, port):
	authurl = globals.https + ip + ":" + str(
		port) + "/ossim/session/login.php"
	url = globals.https + ip + ":" + str(
		port) + "/ossim/conf/index.php?m_opt=configuration&sm_opt=administration&h_opt=main"
	usersurl = globals.https + ip + ":" + str(
		port) + "/ossim/session/getusers.php"
	ossimpass = getpass.getpass(
		Fore.CYAN + Style.BRIGHT + "[!] Enter OSSIM Admin Password: " +
		Style.RESET_ALL)

	ossimpasswordb64 = base64.b64encode(ossimpass.encode("utf-8"))
	base64string = str(ossimpasswordb64, "utf-8")
	params = {
		'embed': '',
		'bookmark_string': '',
		'user': 'admin',
		'passu': ossimpass,
		'pass': base64string
	}

	try:
		s = requests.Session()
		s.post(authurl, data=params, verify=False)
		admin = s.get(url, verify=False)
		users = s.post(usersurl, verify=False)
		globals.ossim_messages(8)
		items = re.findall(
			'<!\\[CDATA\\[([a-z@.]*)', users.text, flags=re.IGNORECASE)
		for item in items:
			if item:
				print("[!] " + item)
		globals.ossim_messages(9)
		df = pandas.read_html(admin.text)

		loginconfig = df[4]
		parameter = 17  # first login parameter

		# iterate over rows with iterrows()
		for index, row in loginconfig.iterrows():
			pattern = r"name=\'value_" + re.escape(
				str(parameter)) + r"+\'    value=\'.*\' "
			match = re.findall(pattern, admin.text)

			if match:
				value = re.split("value=", str(match))[1]
				print("[!] " + row[0] + ": " + value[:-3])
			else:
				print("[!] " + row[0] + ": Default Value")
			parameter += 1

		globals.ossim_messages(10)
		passwordpolicy = df[7]
		parameter = 38  # first password parameter

		# iterate over rows with iterrows()
		for index, row in passwordpolicy.iterrows():
			pattern = r"name=\'value_" + re.escape(
				str(parameter)) + r"+\'    value=\'.*\' "
			match = re.findall(pattern, admin.text)

			if match:
				value = re.split("value=", str(match))[1]
				print("[!] " + row[0] + ": " + value[:-3])
			else:
				print("[!] " + row[0] + ": Default Value")
			parameter += 1

	except Exception as e:
		logging.error(e, exc_info=True)

# %%%%%%%%%% The End %%%%%%%%%%#
