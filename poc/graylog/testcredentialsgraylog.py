#!/usr/bin/env python3

# Graylog Tes Default OVA/AMI Credentials Web: admin/admin SSH: ubuntu/ubuntu

#%%%%%%%%%%% Libraries %%%%%%%%%%%#

import colorama
import json
import logging
import paramiko
import requests
import urllib3
from colorama import Fore, Style

colorama.init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#%%%%%%%%%%% Constants %%%%%%%%%%%#

SEPARATOR = "[*] {0} [*]".format('=' * 110)

#%%%%%%%%%% Functions %%%%%%%%%#

def test_web_credentials(graylogip):

    url = "http://"+graylogip+":9000/api/system/sessions"
    params = {'username':'admin','password':'admin','host':graylogip} #default web interface creds
    headers = {'X-Requested-By': 'XMLHttpRequest'}

    try:
        response = requests.post(url, json=params, headers=headers, verify=False)

        if response.status_code == 200:
            print(SEPARATOR)
            print("[!] Graylog Web Interface Default Credentials Found!")
            print(SEPARATOR)
            print("[!] Username: "+Fore.RED+Style.BRIGHT+"admin")
            print(Style.RESET_ALL + "[!] Password: "+Fore.RED+Style.BRIGHT+"admin")
            print(Style.RESET_ALL + SEPARATOR)
        else:
            print(SEPARATOR)
            print("[!] Graylog Web Interface Default Credentials Not Found, Try Bruteforce Module")
            print(SEPARATOR)

    except Exception as e:
        logging.error(e, exc_info=True)

def test_ssh_credentials(graylogip):

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(graylogip, username='ubuntu', password='ubuntu')
        print("[!] Graylog SSH Default Credentials Found!")
        print(SEPARATOR)
        print("[!] Username: " + Fore.RED + Style.BRIGHT + "ubuntu")
        print(Style.RESET_ALL + "[!] Password: " + Fore.RED + Style.BRIGHT + "ubuntu")
        print(Style.RESET_ALL + SEPARATOR)

    except paramiko.AuthenticationException:
        print(SEPARATOR)
        print("[!] Graylog SSH Default Credentials Not Found")
        print(SEPARATOR)
        pass

#%%%%%%%%%% The End %%%%%%%%%%#
