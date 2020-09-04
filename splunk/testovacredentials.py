#!/usr/bin/env python3

# Splunk Test Default VMWare OVA SSH Credentials:
# root/changemenow and splunk/changeme

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import nmap
import globals
import logging
import paramiko


from globals import SSH_PORT

# %%%%%%%%%% Functions %%%%%%%%%#


def ova_credentials(ip, user, password):

	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	mess = [user, password]
	try:
		ssh.connect(ip, username=user, password=password)
		globals.splunk_messages(10)
		globals.messages(9, mess)

	except paramiko.AuthenticationException:
		globals.splunk_messages(11, mess)


def test_ova_credentials(ip):

	nm = nmap.PortScanner()

	try:
		nm.scan(hosts=ip, arguments='-sT -T4 -p 22')

		if nm[ip]['tcp'][SSH_PORT]['state'] == 'open':
			ova_credentials(ip, "splunk", "changeme")
			ova_credentials(ip, "root", "changemenow")

	except Exception as e:
		logging.error(e, exc_info=True)

# %%%%%%%%%% The End %%%%%%%%%%#
