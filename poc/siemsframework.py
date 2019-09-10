#!/usr/bin/env python3

"""
------------------------------------------------------------------------------
	SIEMS FRAMEWORK - Agosto 2019 - Yamila Levalle @ylevalle
------------------------------------------------------------------------------
"""

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import colorama
from colorama import Fore, Style
import os

from graylog.bruteforcegraylog import graylog_brute
from graylog.testcredentialsgraylog import test_web_credentials, test_ssh_credentials
from graylog.obtainmongodbcredentials import test_mongo_credentials
from graylog.obtaincredentialsrestapi import obtain_ldap_credentials
from graylog.alarmcallback import alarm_callback
from graylog.obtaininputsrestapi import obtain_inputs

from ossim.bruteforceossim import ossim_brute
from ossim.obtainconfigossim import ossim_config
from ossim.maliciousaction import create_policy, generate_ssh_event

from scanning import input_ip, scan_network, scan_host

from splunk.obtainsysteminfo import obtain_system_info
from splunk.obtainpwds import obtain_credentials
from splunk.installshell import install_app
from splunk.bruteforcesplunk import bruteforce_splunk
from splunk.readfile import read_file
from splunk.obtainsplunkinfo import obtain_splunk_info
from splunk.testovacredentials import test_ova_credentials

# %%%%%%% Context Variables %%%%%%%#

VERSION = 1.0
SEPARATOR = "[*] {0} [*]".format('=' * 110)

# %%%%%%%%%%% Functions %%%%%%%%%%%#

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
	print(Fore.CYAN + Style.BRIGHT + b)

# %%%%%%%%%% Menu %%%%%%%%%#

def print_main_menu():

	print(SEPARATOR)
	print(Fore.CYAN + Style.BRIGHT + "[!] Select from the menu:")
	print(SEPARATOR)

	main_menu = ["	[1] Scan and Detect SIEM",
				 "	[2] Find SIEMs on the network",
				 "	[3] Update SIEMs Framework",
				 "	[4] Update Supporting Components",
				 "	[0] Exit SIEMs Framework"]

	for i in main_menu:
		print(i)

	print(SEPARATOR)
	choice = input(Fore.CYAN + Style.BRIGHT + "[!] Enter your selection: " + Style.RESET_ALL)

	return choice

def print_attack_menu(siemdetected):

	print(SEPARATOR)
	print(Fore.CYAN + Style.BRIGHT + "[!] Select attack from the menu:")
	print(SEPARATOR)

	splunk_menu = [
		"	[1] Dictionary Attack on Splunk Server or Universal Forwarder User Admin via "
		"Management Port",
		"	[2] Obtain Server and Session Information via Web Interface",
		"	[3] Obtain Server or Universal Forwarder System Information via Management Port (Admin "
		"Credentials Needed)",
		"	[4] Obtain Splunk Server Apps Stored Passwords with Secret (Admin Credentials Needed)",
		"	[5] Read /etc/shadow file from Splunk Server (Linux Only - Admin Credentials Needed)",
		"	[6] Deploy Malicious App to Forwarders via Deployment Server (Admin Credentials "
		"Needed)",
		"	[7] Upload Malicious App to Splunk Server or Universal Forwarder (Admin Credentials "
		"Needed)",
		"	[8] Test for Splunk VMware OVA Default Credentials",
		"	[0] Return to Main Menu"]

	graylog_menu = ["	[1] Dictionary Attack on Graylog Web Interface User Admin",
					"	[2] Test for AMI/OVA Default Credentials",
					"	[3] Test connection to MongoDB and Obtain Credentials for LDAP and AWS",
					"	[4] Obtain Configuration and Credentials for LDAP and AWS from REST API ("
					"Admin Credentials Needed)",
					"	[5] Obtain Credentials in Graylog Inputs from REST API (Admin Credentials "
					"Needed)",
					"	[6] Create and Test Alarm Callback to Obtain Reverse Shell (Admin "
					"Credentials Needed)",
					"	[0] Return to Main Menu"]

	ossim_menu = ["	[1] Dictionary Attack on OSSIM Web Interface User Admin",
				  "	[2] Obtain OSSIM Server Configuration Information (Admin Credentials Needed)",
				  "	[3] Upload OSSIM Malicious Policy and Action to Obtain Reverse Shell (Admin "
				  "Credentials Needed)",
				  "	[0] Return to Main Menu"]

	if siemdetected == "Splunk":
		for i in splunk_menu:
			print(i)

	if siemdetected == "Graylog":
		for i in graylog_menu:
			print(i)

	if siemdetected == "OSSIM":
		for i in ossim_menu:
			print(i)

	print(SEPARATOR)
	choice = input(Fore.CYAN + Style.BRIGHT + "[!] Enter your selection: " + Style.RESET_ALL)

	return choice

def print_app_menu(siemdetected):

	print(SEPARATOR)
	print(Fore.CYAN + Style.BRIGHT + "[!] Select attack from the menu:")
	print(SEPARATOR)

	app_menu = ["	[1] Linux Splunk Server or Universal Forwarder Reverse Shell",
				"	[2] Linux Splunk Server or Universal Forwarder Bind Shell",
				"	[3] Windows Splunk Server Reverse Shell",
				"	[4] Windows Splunk Server Bind Shell",
				"	[5] Windows Splunk Universal Forwarder Add Administrator User",
				"	[6] Windows Splunk Universal Forwarder Executable Bind Shell",
				"	[0] Return to Attack Menu"]

	for i in app_menu:
		print(i)

	print(SEPARATOR)
	choice = input(Fore.CYAN + Style.BRIGHT + "[!] Enter your selection: " + Style.RESET_ALL)

	return choice

# %%%%%%%%%% Menu Choices %%%%%%%%%#

def attack_choice(siemdetected, ip):

	choiceerror = 0
	attackchoice = print_attack_menu(siemdetected)

	if siemdetected == "Splunk" and attackchoice == "1":  # Bruteforce Splunk Admin
		bruteforce_splunk(ip)
	elif siemdetected == "Splunk" and attackchoice == "2":  # Obtain Server Information
		obtain_splunk_info(ip)
	elif siemdetected == "Splunk" and attackchoice == "3":  # Obtain System Information
		obtain_system_info(ip)
	elif siemdetected == "Splunk" and attackchoice == "4":  # Obtain Splunk Passwords
		obtain_credentials(ip)
	elif siemdetected == "Splunk" and attackchoice == "5":  # Read /etc/shadow
		read_file(ip)
	elif siemdetected == "Splunk" and attackchoice == "7":  # Upload Malicious App
		app_choice(siemdetected, ip)
	elif siemdetected == "Splunk" and attackchoice == "8":  # Test OVA Credentials
		test_ova_credentials(ip)
	elif siemdetected == "Graylog" and attackchoice == "1":  # Bruteforce Graylog
		graylog_brute(ip)
	elif siemdetected == "Graylog" and attackchoice == "2":  # Test Default Credentials
		test_web_credentials(ip)
		test_ssh_credentials(ip)
	elif siemdetected == "Graylog" and attackchoice == "3":  # Test MongoDB
		test_mongo_credentials(ip)
	elif siemdetected == "Graylog" and attackchoice == "4":  # Obtain credentials from API
		obtain_ldap_credentials(ip)
	elif siemdetected == "Graylog" and attackchoice == "5":  # Inputs from API
		obtain_inputs(ip)
	elif siemdetected == "Graylog" and attackchoice == "6":  # Alarm Callback
		alarm_callback(ip)
	elif siemdetected == "OSSIM" and attackchoice == "1":  # Bruteforce OSSIM
		ossim_brute(ip)
	elif siemdetected == "OSSIM" and attackchoice == "2":  # Obtain Configuration
		ossim_config(ip)
	elif siemdetected == "OSSIM" and attackchoice == "3":  # Malicious Policy and Action
		create_policy(ip)
	elif attackchoice == "0":  # Return
		main_choice()

	else:
		print("[!] Choice error please select again:")
		attack_choice(siemdetected, ip)
		choiceerror = 1

	if attackchoice != "0" and choiceerror != 1:  # Not return and not error

		choice3 = input(
			Fore.CYAN + Style.BRIGHT + "[!] Do you want to return to the attack menu (Y/N): " +
			Style.RESET_ALL)

		if choice3.lower() == "y":
			attack_choice(siemdetected, ip)
		else:
			main_choice()


def app_choice(siemdetected, ip):

	appchoice = print_app_menu(siemdetected)
	appname = None

	if siemdetected == "Splunk" and appchoice == "1":  # Linux Reverse Shell
		appname = "rshell.tar.gz"
	if siemdetected == "Splunk" and appchoice == "2":  # Linux Bind Shell
		appname = "bshell.tar.gz"
	if siemdetected == "Splunk" and appchoice == "3":  # Windows Reverse Shell
		appname = "wrshell.tar.gz"
	if siemdetected == "Splunk" and appchoice == "4":  # Windows Bind Shell
		appname = "wbshell.tar.gz"
	if siemdetected == "Splunk" and appchoice == "5":  # Windows UF Add User
		appname = "wadduser.tar.gz"
	if siemdetected == "Splunk" and appchoice == "6":  # Windows UF Bind Shell
		appname = "wbshellexe.tar.gz"
	if appchoice == "0":  # Return
		attack_choice(siemdetected, ip)

	if appchoice != "0" and appname:  # Not return and valid app selection

		install_app(ip, appname)

		choice3 = input(
			Fore.CYAN + Style.BRIGHT + "[!] Do you want to return to the attack menu (Y/N): " +
			Style.RESET_ALL)

		if choice3.lower() == "y":
			attack_choice(siemdetected, ip)
		else:
			main_choice()


def main_choice():
	choice = print_main_menu()
	siemdetected = "None"
	siemsdetected = {}

	if choice == "1":  # Scan and Detect SIEM

		ip = input_ip()
		siemdetected = scan_host(ip)

		choice2 = input(
			Fore.CYAN + Style.BRIGHT + "[!] Do you want to launch the " + siemdetected + " attack "
			"module (Y/N): "+ Style.RESET_ALL)

		if choice2.lower() == "y":
			attack_choice(siemdetected, ip)

		else:
			main_choice()

	elif choice == "2":  # Find SIEM on the Network

		ips = scan_network()

		print(SEPARATOR)
		print(Fore.CYAN + Style.BRIGHT + "[!] SIEMs Detected on the Network:")
		print(SEPARATOR)

		for host in ips:
			siemdetected = scan_host(host)
			siemsdetected[host] = siemdetected

		siemchoice = input(
			Fore.CYAN + Style.BRIGHT + "[!] Enter the IP address of the SIEM to attack: " +
			Style.RESET_ALL)

		choice2 = input(Fore.CYAN + Style.BRIGHT + "[!] Do you want to launch the " +
						siemsdetected[siemchoice] + " attack module (Y/N): " + Style.RESET_ALL)

		if choice2.lower() == "y":
			attack_choice(siemsdetected[siemchoice], siemchoice)

		else:
			main_choice()

	elif choice == "0":
		quit()

	else:
		print("[!] Choice error please select again:")
		main_choice()


# %%%%%%%%%% Main %%%%%%%%%#

def main():
	os.system('cls' if os.name == 'nt' else 'clear')
	colorama.init(autoreset = "True")
	banner()
	main_choice()

main()

# %%%%%%%%%% The End %%%%%%%%%%#
