#!/usr/bin/env python3

# Splunk Test Default VMWare OVA SSH Credentials: root/changemenow and splunk/changeme

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import colorama
import logging
import nmap
import paramiko
from colorama import Fore, Style

colorama.init()

# %%%%%%%%%%% Constants %%%%%%%%%%%#

SEPARATOR = "[*] {0} [*]".format('=' * 110)
SSH_PORT = 22

# %%%%%%%%%% Functions %%%%%%%%%#

def test_credentials(splunkip, user, password):

	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	try:
		ssh.connect(splunkip, username = user, password = password)
		print("[!] Splunk VMWare OVA SSH Default Credentials Found!")
		print(SEPARATOR)
		print("[!] Username: " + Fore.RED + Style.BRIGHT + user)
		print(Style.RESET_ALL + "[!] Password: " + Fore.RED + Style.BRIGHT + password)
		print(Style.RESET_ALL + SEPARATOR)

	except paramiko.AuthenticationException:
		print("[!] Splunk SSH Default Credential for " + user + " Not Found")
		print(SEPARATOR)

def test_ova_credentials(splunkip):

	nm = nmap.PortScanner()

	try:
		nm.scan(hosts = splunkip, arguments = '-sT -T4 -p 22')

		if nm[splunkip]['tcp'][SSH_PORT]['state'] == 'open':
			print(SEPARATOR)
			test_credentials(splunkip, "splunk", "changeme")
			test_credentials(splunkip, "root", "changemenow")

	except Exception as e:
		logging.error(e, exc_info = True)

# %%%%%%%%%% The End %%%%%%%%%%#
