#!/usr/bin/env python3

# QRadar information for API

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import globals

from colorama import Fore, Style
from qradar4py.api import QRadarApi

# %%%%%%%%%% Functions %%%%%%%%%#


def qradar_info(ip, port):
    api = input("[!] Enter API Key of QRadar: ")
    url = "https://" + ip + ":" + str(port)
    api = QRadarApi(url, api, version='9.1', verify=False)

    status, resp = api.config.get_deployment_hosts()
    if status == 200:
        globals.qradar_messages(3)
        for item in resp:
            print(Style.RESET_ALL + "[!] Hostname: " + Fore.RED + Style.BRIGHT
                  + item['hostname'])
            print(Style.RESET_ALL + "[!] Version QRadar: " + Fore.RED +
                  Style.BRIGHT + item['version'])
            print(Style.RESET_ALL + "[!] Public IP: " + Fore.RED +
                  Style.BRIGHT + item['public_ip'])
            print(Style.RESET_ALL + "[!] Private IP: " + Fore.RED +
                  Style.BRIGHT + item['private_ip'])
            print(Style.RESET_ALL + "[!] License Serial Number: " + Fore.RED +
                  Style.BRIGHT + str(item['license_serial_number']))
            print(Style.RESET_ALL + globals.SEPARATOR)

    status, resp = api.config.get_access_users()
    if status == 200:
        globals.qradar_messages(4)

        for item in resp:
            print(Style.RESET_ALL + "[!] Username: " + Fore.RED +
                  Style.BRIGHT + str(item['username']))

    status, resp = api.config.get_network_hierarchy_networks()
    if status == 200:
        globals.qradar_messages(5)
        for item in resp:
            print(Style.RESET_ALL + "[!] Network: " + Fore.RED +
                  Style.BRIGHT + str(item['name']) + " - " + str(item['cidr']))

# %%%%%%%%%% The End %%%%%%%%%%#
