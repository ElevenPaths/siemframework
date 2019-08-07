#!/usr/bin/env python3

# Nmap Scanning Module

#%%%%%%%%%%% Libraries %%%%%%%%%%%#

import nmap
import requests
from colorama import Fore, Back, Style
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#%%%%%%%%%%% Constants %%%%%%%%%%%#

separator = "[*] ============================================================================================================== [*]"

#%%%%%%%%%%% Functions %%%%%%%%%%%#

def input_ip():

	siemip = input("[!] Enter IP address of the SIEM: ")
	return siemip

def scan_host(ip):

	siemdetected = "None"
	siemip=ip

	try:
		nm = nmap.PortScanner()
		nm.scan(hosts=siemip,arguments='-sT -T4 -p 8089,443,9000')

		if (nm[siemip]['tcp'][8089]['state'] == 'open' or nm[siemip]['tcp'][443]['state'] == 'open' or nm[siemip]['tcp'][9000]['state'] == 'open'):

			print('[!] IP Address: %s' % ip)
			print('[!] Hostname: %s' % nm[siemip].hostname())
			print('[!] State: %s' % nm[siemip].state())
			print(separator)

			for proto in nm[siemip].all_protocols():
				lport = nm[siemip][proto].keys()
		
				for port in lport:
					if (nm[siemip][proto][port]['state']=='open'):
						print("[!] Port: %s State: %s" % (port, nm[siemip][proto][port]['state']))

						if (nm[siemip]['tcp'][8089]['state']=='open'):
							url = "https://"+siemip+":8089"
							try:
								response = requests.get(url,verify=False)
								if("splunkd" in response.text):
									siemdetected="Splunk"

							except Exception as e:
								print(e)
								pass

						elif (nm[siemip]['tcp'][9000]['state']=='open'):
							url = "http://"+siemip+":9000"
						
							try:
								response = requests.get(url)
								if("Graylog Web Interface" in response.text):
									siemdetected="Graylog"

							except Exception as e:
								print(e)
								pass

						elif (nm[siemip]['tcp'][443]['state'] == 'open'):
							url = "https://"+siemip+"/ossim/session/login.php"

							try:
								response = requests.get(url,verify=False)
								if ("AlienVault OSSIM" in response.text):
									siemdetected = "OSSIM"

							except Exception as e:
								print(e)
								pass
	except Exception as e:
		print(e)
		pass

	if (siemdetected != "None"):
		print(separator)
		print("[!] The SIEM detected is: "+Fore.RED+Style.BRIGHT+siemdetected)
		print(separator)

	return siemdetected

def scan_network():

	print(separator)
	siemnet = input("[!] Enter network to scan for SIEMs in CIDR notation, for example: 192.168.1.0/24: ")

	try:
		nm = nmap.PortScanner()
		nm.scan(hosts=siemnet,arguments='-sP -PS8089,443,9000')
		return nm.all_hosts()

	except Exception as e:
		print(e)
		pass

#%%%%%%%%%% The End %%%%%%%%%%#


