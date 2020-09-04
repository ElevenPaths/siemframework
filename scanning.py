#!/usr/bin/env python3

# nmap Scanning Module

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import re
import nmap
import urllib3
import logging
import globals
import requests

from colorama import Fore
from colorama import Style
from globals import http
from globals import https
from globals import SEPARATOR
from globals import HTTPS_TCP_PORT
from globals import SPLUNK_TCP_PORT
from globals import GRAYLOG_TCP_PORT
from globals import ELASTIC_TCP_PORT

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# %%%%%%%%%%% Functions %%%%%%%%%%%#


def input_ip():
	siemip = input(
		Fore.CYAN + Style.NORMAL + "[!] Enter IP address of the SIEM: ")
	if re.search(globals.ip_val, siemip):
		return siemip
	else:
		return ''


def input_port():
	siemport = input(
		Fore.CYAN + Style.NORMAL +
		"[!] Enter Port use of the SIEM: {Enter for default}")
	if siemport == '':
		siemport = 0
		return siemport
	elif 0 <= int(siemport) <= 65535:
		return siemport
	else:
		return ''


def input_net():
	siemnet = input(
		Fore.CYAN + Style.NORMAL +
		"[!] Enter network to scan for SIEMs in CIDR notation, "
		"for example: 192.168.1.0/24: ")
	return siemnet


def scan_host(ip, port):

	siemdetected = "None"
	siemip = ip
	siemport = port

	try:
		argument = \
			'-sT -T4 -Pn -p ' + str(HTTPS_TCP_PORT) + ',' + \
			str(GRAYLOG_TCP_PORT) + ',' + str(SPLUNK_TCP_PORT) + ',' + \
			str(ELASTIC_TCP_PORT) + ',' + str(siemport)
		nm = nmap.PortScanner()
		nm.scan(hosts=siemip, arguments=argument)

		if nm[
			siemip]['tcp'][SPLUNK_TCP_PORT]['state'] == 'open' or nm[
			siemip]['tcp'][HTTPS_TCP_PORT]['state'] == 'open' or nm[
			siemip]['tcp'][GRAYLOG_TCP_PORT]['state'] == 'open' or nm[
			siemip]['tcp'][ELASTIC_TCP_PORT]['state'] == 'open' or nm[
			siemip]['tcp'][int(siemport)]['state'] == 'open':

			print('[!] IP Address: %s' % ip)
			print('[!] Hostname: %s' % nm[siemip].hostname())
			print('[!] State: %s' % nm[siemip].state())
			print(SEPARATOR)

			if nm[siemip]['tcp'][SPLUNK_TCP_PORT]['state'] == 'open':
				siemdetected = splunk_detect(siemip, str(SPLUNK_TCP_PORT))
			elif nm[siemip]['tcp'][GRAYLOG_TCP_PORT]['state'] == 'open':
				siemdetected = graylog_detect(siemip, str(GRAYLOG_TCP_PORT))
			elif nm[siemip]['tcp'][ELASTIC_TCP_PORT]['state'] == 'open':
				siemdetected = elasticsiem_detect(siemip, str(ELASTIC_TCP_PORT))
			elif nm[siemip]['tcp'][HTTPS_TCP_PORT]['state'] == 'open':
				siemdetected = ossim_detect(siemip, str(HTTPS_TCP_PORT))
				siemdetected = qradar_detect(siemip, str(HTTPS_TCP_PORT))
				siemdetected = mcafee_detect(siemip, str(HTTPS_TCP_PORT))
				siemdetected = smonster_detect(siemip, str(HTTPS_TCP_PORT))
			elif nm[
				siemip]['tcp'][int(siemport)]['state'] == 'open' and siemport == str(port):
				siemdetected = splunk_detect(siemip, port)
				siemdetected = graylog_detect(siemip, port)
				siemdetected = ossim_detect(siemip, port)
				siemdetected = qradar_detect(siemip, port)
				siemdetected = mcafee_detect(siemip, port)
				siemdetected = smonster_detect(siemip, port)
				siemdetected = elasticsiem_detect(siemip, port)

	except Exception as e:
		logging.error(e, exc_info=True)

	return siemdetected


def splunk_detect(siemip, siemport):
	url = https + siemip + ":" + siemport
	try:
		response = requests.get(url, verify=False)
		if "splunkd" in response.text:
			siemdetected = "Splunk"
			globals.messages(5, [siemdetected, siemport])
			return siemdetected
	except Exception as e:
		logging.error(e, exc_info=True)


def graylog_detect(siemip, siemport):
	url = http + siemip + ":" + siemport
	try:
		response = requests.get(url)
		if "Graylog Web Interface" in response.text:
			siemdetected = "Graylog"
			globals.messages(5, [siemdetected, siemport])
			return siemdetected
	except Exception as e:
		logging.error(e, exc_info=True)


def elasticsiem_detect(siemip, siemport):
	url = http + siemip + ":" + siemport + '/app/siem'
	try:
		response = requests.get(url)
		if "Elastic" in response.text and "elasticsiem" in response.headers[
			'kbn-name']:
			siemdetected = "ElasticSIEM"
			globals.messages(5, [siemdetected, siemport])
			return siemdetected
	except Exception as e:
		logging.error(e, exc_info=True)


def ossim_detect(siemip, siemport):
	url = https + siemip + ":" + siemport + "/ossim/session/login.php"
	try:
		response = requests.get(url, verify=False)
		if "AlienVault OSSIM" in response.text:
			siemdetected = "OSSIM"
			globals.messages(5, [siemdetected, siemport])
			return siemdetected
	except Exception as e:
		logging.error(e, exc_info=True)


def qradar_detect(siemip, siemport):
	url = https + siemip + ":" + siemport + "/console/"
	try:
		response = requests.get(url, verify=False)
		if "QRadar" in response.headers['Server']:
			siemdetected = "QRadar"
			globals.messages(5, [siemdetected, siemport])
			return siemdetected
	except Exception as e:
		logging.error(e, exc_info=True)


def mcafee_detect(siemip, siemport):
	url = https + siemip + ":" + siemport
	try:
		response = requests.get(url, verify=False)
		if 'McAfee' in response.text and 'SIEM' in response.text:
			siemdetected = "McAfee"
			globals.messages(5, [siemdetected, siemport])
			return siemdetected
	except Exception as e:
		logging.error(e, exc_info=True)


def smonster_detect(siemip, siemport):
	url = https + siemip + ":" + siemport
	try:
		response = requests.get(url, verify=False)
		if 'title>SIEMonster ' in response.text:
			siemdetected = "SIEMonster"
			globals.messages(5, [siemdetected, siemport])
			return siemdetected
	except Exception as e:
		logging.error(e, exc_info=True)


def scan_network(siemnet):

	try:
		nm = nmap.PortScanner()
		nm.scan(hosts=siemnet, arguments='-PS -Pn -p 8089,443,9000')
		return nm.all_hosts()

	except Exception as e:
		logging.error(e, exc_info=True)

# %%%%%%%%%% The End %%%%%%%%%%#
