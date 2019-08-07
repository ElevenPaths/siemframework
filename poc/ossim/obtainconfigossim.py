#!/usr/bin/env python3

# OSSIM Obtain Configuration Information

#%%%%%%%%%%% Libraries %%%%%%%%%%%#

import base64
import requests
from colorama import Fore, Style
from colorama import init
init()
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import re
import pandas
import getpass

#%%%%%%%%%%% Constants %%%%%%%%%%%#

separator = "[*] ============================================================================================================== [*]"

#%%%%%%%%%% Functions %%%%%%%%%#

def ossimconfig(ossimip):

    authurl = url = "https://"+ossimip+"/ossim/session/login.php"
    url = "https://"+ossimip+"/ossim/conf/index.php?m_opt=configuration&sm_opt=administration&h_opt=main"
    usersurl = "https://"+ossimip+"/ossim/session/getusers.php"
    ossimpass = getpass.getpass(Fore.CYAN+Style.BRIGHT+"[!] Enter OSSIM Admin Password: "+Style.RESET_ALL)

    ossimpasswordb64 = base64.b64encode(ossimpass.encode("utf-8"))
    base64string = str(ossimpasswordb64, "utf-8")
    params = {'embed':'','bookmark_string':'','user':'admin','passu':ossimpass,'pass':base64string}

    try:
        s = requests.Session()
        auth = s.post(authurl,data=params,verify=False)
        admin = s.get(url, verify=False)
        users = s.post(usersurl, verify=False)

        print(separator)
        print("[!] OSSIM Users, Emails and Company")
        print(separator)

        items = re.findall('<!\\[CDATA\\[([a-z@.]*)', users.text, flags=re.IGNORECASE)
        for item in items:
                if (item):
                    print ("	[!] "+item)

        print(separator)
        print("[!] OSSIM Login Methods and Parameters")
        print(separator)

        df = pandas.read_html(admin.text)

        loginconfig = df[4]
        parameter=17 #first login parameter

        for index, row in loginconfig.iterrows(): # iterate over rows with iterrows()
            pattern = r"name=\'value_" + re.escape(str(parameter)) + r"+\'    value=\'.*\' "
            match = re.findall(pattern, admin.text)

            if(match):
                values = str(match)
                value = re.split("value=",values)[1]
                print("	[!] "+row[0]+": "+value[:-3])
            else:
                print("	[!] "+row[0]+": Default Value")
            parameter+=1

        print(separator)
        print("[!] OSSIM Password Policies")
        print(separator)

        passwordpolicy = df[7]
        parameter = 38  # first password parameter

        for index, row in passwordpolicy.iterrows():  # iterate over rows with iterrows()
            pattern = r"name=\'value_" + re.escape(str(parameter)) + r"+\'    value=\'.*\' "
            match = re.findall(pattern, admin.text)

            if (match):
                values = str(match)
                value = re.split("value=", values)[1]
                print("	[!] " + row[0] + ": " + value[:-3])
            else:
                print("	[!] " + row[0] + ": Default Value")
            parameter += 1
        print(separator)

    except Exception as e:
        pass

#%%%%%%%%%% The End %%%%%%%%%%#



