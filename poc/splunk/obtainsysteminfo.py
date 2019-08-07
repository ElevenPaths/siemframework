#!/usr/bin/env python3

# Obtain Splunk System Information

#%%%%%%%%%%% Libraries %%%%%%%%%%%#

import sys
import getpass
sys.path.append('../')
import splunklib.client as client

#%%%%%%%%%%%% Constants %%%%%%%%%%%%%#

separator = "[*] ============================================================================================================== [*]"

#%%%%%%%%%%% Functions %%%%%%%%%%%#

def obtainsysteminfo(splunkServer):

    print(separator)
    splunkAdmin = input("[!] Enter Splunk Admin (Default admin): ")
    splunkPassword = getpass.getpass("[!] Enter Splunk Password: ")

    splunkService = client.connect(host=splunkServer, port=8089, username=splunkAdmin, password=splunkPassword)
    content = splunkService.info

    print(separator)
    print("[!] Splunk Info:")
    print(separator)

    for key in sorted(content.keys()):
        value = content[key]
        if isinstance(value, list):
            print("[*] %s:" % key)
            for item in value: print("[!]    %s" % item)
        else:
            print("[*] %s: %s" % (key, value))

    print(separator)
    print("[!] Splunk Settings:")
    print(separator)

    content = splunkService.settings.content

    for key in sorted(content.keys()):
        value = content[key]
        print("[*] %s: %s" % (key, value))
    print(separator)

#%%%%%%%%%% The End %%%%%%%%%%#



