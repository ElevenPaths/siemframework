#!/usr/bin/env python3

# Graylog Tes Default OVA/AMI Credentials Web: admin/admin SSH: ubuntu/ubuntu

#%%%%%%%%%%% Libraries %%%%%%%%%%%#

import requests
import colorama
colorama.init()
from colorama import Fore, Style
import paramiko
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import json

#%%%%%%%%%%% Constants %%%%%%%%%%%#

separator = "[*] ============================================================================================================== [*]"

#%%%%%%%%%% Functions %%%%%%%%%#

def testwebcredentials(graylogip):

    url = "http://"+graylogip+":9000/api/system/sessions"
    params = {'username':'admin','password':'admin','host':graylogip} #default web interface credentials
    headers = {'X-Requested-By': 'XMLHttpRequest'}

    try:
        response = requests.post(url, json=params, headers=headers, verify=False)

        if response.status_code == 200:
            print(separator)
            print("[!] Graylog Web Interface Default Credentials Found!")
            print(separator)
            print("[!] Username: "+Fore.RED+Style.BRIGHT+"admin")
            print(Style.RESET_ALL + "[!] Password: "+Fore.RED+Style.BRIGHT+"admin")
            print(Style.RESET_ALL + separator)
        else:
            print(separator)
            print("[!] Graylog Web Interface Default Credentials Not Found, Try Bruteforce Module")
            print(separator)

    except Exception as e:
        print(e)
        pass

def testsshcredentials(graylogip):

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(graylogip, username='ubuntu', password='ubuntu')
        print("[!] Graylog SSH Default Credentials Found!")
        print(separator)
        print("[!] Username: " + Fore.RED + Style.BRIGHT + "ubuntu")
        print(Style.RESET_ALL + "[!] Password: " + Fore.RED + Style.BRIGHT + "ubuntu")
        print(Style.RESET_ALL + separator)

    except paramiko.AuthenticationException:
        print(separator)
        print("[!] Graylog SSH Default Credentials Not Found")
        print(separator)
        pass

#%%%%%%%%%% The End %%%%%%%%%%#
