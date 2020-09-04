#!/usr/bin/env python3

# Variables and Functions globals in Framework

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

from colorama import Fore, Style

# %%%%%%%%%%% Constants %%%%%%%%%%%#

SEPARATOR = "[*] {0} [*]".format('=' * 110)
SSH_PORT = 22
HTTPS_TCP_PORT = 443
SPLUNK_TCP_PORT = 8089
GRAYLOG_TCP_PORT = 9000
ELASTIC_TCP_PORT = 5601

https = "https://"
http = "http://"


ip_val = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'''
net_val = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)/(2[0-4]|[0-1]?[0-9][0-9]?)$'''

agents = [
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)'
    ' Chrome/79.0.3945.88 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/47.0',
    'Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/42.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)'
    ' Chrome/51.0.2704.106 Safari/537.36 OPR/38.0.2220.41'
]


# %%%%%%%%%%% Menus %%%%%%%%%%%#
main_menu = ["Scan and Detect SIEM",
             "Find SIEMs on the network"]
# "Update SIEMs Framework",
# "Update Supporting Components"

splunk_menu = ["Dictionary Attack on Splunk Server or Universal Forwarder User"
               " Admin via Management Port",
               "Obtain Server and Session Information via Web Interface",
               "Obtain Server or Universal Forwarder System Information via "
               "Management Port (Admin Credentials Needed)",
               "Obtain Splunk Server Apps Stored Passwords with Secret "
               "(Admin Credentials Needed)",
               "Read /etc/shadow file from Splunk Server "
               "(Linux Only - Admin Credentials Needed)",
               "Deploy Malicious App to Forwarders via Deployment Server "
               "(Admin Credentials Needed)",
               "Upload Malicious App to Splunk Server or Universal Forwarder "
               "(Admin Credentials Needed)",
               "Test for Splunk VMware OVA Default Credentials"
               ]

graylog_menu = ["Dictionary Attack on Graylog Web Interface User Admin",
                "Test for AMI/OVA Default Credentials",
                "Obtain Configuration and Credentials for LDAP and AWS from "
                "REST API (Admin Credentials Needed)",
                "Obtain Credentials in Graylog Inputs from REST API "
                "(Admin Credentials Needed)",
                "Create and Test Alarm Callback to Obtain Reverse Shell "
                "(Admin Credentials Needed)"
                ]

ossim_menu = ["Dictionary Attack on OSSIM Web Interface User Admin",
              "Obtain OSSIM Server Configuration Information "
              "(Admin Credentials Needed)",
              "Upload OSSIM Malicious Policy and Action to Obtain Reverse "
              "Shell (AdminCredentials Needed)"
              ]

qradar_menu = ["Dictionary Attack on QRadar Web Interface User Admin "
               "(Very Slow)",
               "Dictionary Attack on QRadar with API Key of User Admin",
               "Obtain QRadar Server Configuration Information "
               "(API Key Needed)",
               "Obtain list of usernames of databases Ariel on QRadar "
               "(API Key Needed)"
               ]

mcafee_menu = ["Dictionary Attack on McAfee Web Interface User Admin (Slow)",
               "Dictionary Attack on McAfee SSH of User Admin",
               "Obtain McAfee Server Configuration (Admin Credentials Needed)",
               "Obtain McAfee Server Information (Admin Credentials Needed)",
               "Obtain shadow file of server (Admin Credentials Needed)"
               ]

smonster_menu = ["Dictionary Attack on SIEMonster SSH of User Admin",
                 "Obtain SIEMonster Information (Admin Credentials Needed)",
                 "Obtain shadow file of server (Admin Credentials Needed)"
                 ]

elastic_menu = ["Dictionary Attack on ElasticSIEM SSH of User Admin",
                "Obtain ElasticSIEM Server Information "
                "(Admin Credentials Needed)"
                ]

app_menu = ["Linux Splunk Server or Universal Forwarder Reverse Shell",
            "Linux Splunk Server or Universal Forwarder Bind Shell",
            "Windows Splunk Server Reverse Shell",
            "Windows Splunk Server Bind Shell",
            "Windows Splunk Universal Forwarder Add Administrator User",
            "Windows Splunk Universal Forwarder Executable Bind Shell"
            ]

username = "[!] Username: "
password = "[!] Password: "

# %%%%%%%%%%% Functions %%%%%%%%%%%#


def messages(op, message=None):
    if message is None:
        message = []
    print('\n')
    print(Fore.GREEN + Style.BRIGHT + SEPARATOR)
    if op == 1:
        print(Fore.GREEN + Style.BRIGHT + '[!] Select from the menu: ')
    elif op == 2:
        print(Fore.YELLOW + Style.BRIGHT +
              '[!] Choice error please select again: ')
    elif op == 3:
        print(Fore.YELLOW + Style.BRIGHT +
              '[*] IP or Port data error. Try again')
    elif op == 4:
        print(Fore.YELLOW + Style.BRIGHT + '[*] Net data error. Try again')
    elif op == 5:
        print(Fore.YELLOW + "[!] The SIEM detected is: " + Fore.RED +
              Style.BRIGHT + message[0])
        print(Fore.YELLOW + "[!] The SIEM is working on the port: " +
              Fore.RED + Style.BRIGHT + message[1])
    elif op == 6:
        print(Fore.YELLOW + Style.BRIGHT +
              "[!] SIEMs Detected on the Network: ")
    elif op == 7:
        print(Fore.GREEN + Style.BRIGHT + "[!] Dictionary Attack Successful!")
    elif op == 8:
        print(Fore.RED + Style.BRIGHT +
              "[!] Dictionary Attack Not Successful")
    elif op == 9:
        print(Fore.YELLOW + Style.BRIGHT + username +
              Fore.RED + Style.BRIGHT + message[0])
        print(Fore.YELLOW + password + Fore.RED + Style.BRIGHT + message[1])
    elif op == 10:
        print(Fore.RED + Style.BRIGHT + "[*] Authentication Error")

    print(Fore.GREEN + Style.BRIGHT + SEPARATOR + Style.RESET_ALL)


def splunk_messages(op, message=None):
    if message is None:
        message = []
    print(Fore.GREEN + Style.NORMAL + SEPARATOR)
    if op == 1:
        print(Fore.GREEN + Style.NORMAL + "[!] List of Installed Apps:")
    elif op == 2:
        print(Fore.GREEN + Style.NORMAL +
              "[!] Application Successfully Installed "
              + Fore.RED + Style.BRIGHT + message[0])
    elif op == 3:
        print(Fore.RED + Style.NORMAL +
              "[!] Error with the app selection [!]")
    elif op == 4:
        print(Fore.GREEN + Style.NORMAL +
              "[!] Currently stored credentials:")
    elif op == 5:
        print("[*] Credential Name: " + message[0])
        print("[*] Username: " + Fore.RED + Style.BRIGHT + message[1])
        print("[*] Encrypted Password: " + message[2])
        print("[*] Clear Password: " + Fore.RED + Style.BRIGHT + message[3])
    elif op == 6:
        print(Fore.GREEN + Style.NORMAL + "[!] Splunk Server Information")
    elif op == 7:
        print(Fore.GREEN + Style.NORMAL + "[!] Splunk Session Information")
    elif op == 8:
        print(Fore.GREEN + Style.NORMAL + "[!] Splunk Config Web")
    elif op == 9:
        print(Fore.GREEN + Style.NORMAL + "[!] File /etc/shadow content:")
    elif op == 10:
        print(Fore.GREEN + Style.NORMAL +
              "[!] Splunk VMWare OVA SSH Default Credentials Found!")
    elif op == 11:
        print(Fore.GREEN + Style.NORMAL +
              "[!] Splunk SSH Default Credential for "
              + message[0] + " Not Found")

    print(Fore.GREEN + Style.NORMAL + SEPARATOR + Style.RESET_ALL)


def ossim_messages(op, message=None):
    if message is None:
        message = []
    print(Fore.GREEN + Style.NORMAL + SEPARATOR)
    if op == 1:
        print(Fore.GREEN + Style.NORMAL +
              "[!] Start a listener in port 12345, for example nc -lvp 12345")
    elif op == 2:
        print(Fore.GREEN + Style.NORMAL +
              "[!] OSSIM Reverse Shell Action Created with ID " + message[0])
        print(Fore.GREEN + Style.NORMAL +
              "[!] OSSIM Policies CTX Obtained " + message[1])
    elif op == 3:
        print(Fore.RED + Style.NORMAL +
              "[!] Error creating the OSSIM Reverse Shell Action")
    elif op == 4:
        print(Fore.GREEN + Style.NORMAL + "[!] OSSIM New Policy Created")
    elif op == 5:
        print(Fore.GREEN + Style.NORMAL + "[!] Policies Reloaded and Applied")
    elif op == 6:
        print(Fore.RED + Style.NORMAL +
              "[!] Error creating the OSSIM New Policy")
    elif op == 7:
        print(Fore.RED + Style.NORMAL + "[!] SSH Failed Login Event Generated")
        print(Fore.RED + Style.BRIGHT + "[!] Reverse Shell Ready")
    elif op == 8:
        print(Fore.GREEN + Style.NORMAL +
              "[!] OSSIM Users, Emails and Company")
    elif op == 9:
        print(Fore.GREEN + Style.NORMAL +
              "[!] OSSIM Login Methods and Parameters")
    elif op == 10:
        print(Fore.GREEN + Style.NORMAL + "[!] OSSIM Password Policies")

    print(Fore.GREEN + Style.NORMAL + SEPARATOR + Style.RESET_ALL)


def graylog_messages(op):
    print(Fore.GREEN + Style.NORMAL + SEPARATOR)
    if op == 1:
        print(Fore.GREEN + Style.NORMAL +
              "[!] Graylog LDAP Settings and Credentials")
    elif op == 2:
        print(Fore.GREEN + Style.NORMAL +
              "[!] Error obtaining Graylog LDAP Settings and Credentials")
    elif op == 3:
        print(Fore.GREEN + Style.NORMAL +
              "[!] Graylog AWS Settings and Credentials")
    elif op == 4:
        print(Fore.GREEN + Style.NORMAL +
              "[!] Error obtaining Graylog AWS Settings and Credentials")
    elif op == 5:
        print(Fore.GREEN + Style.NORMAL +
              "[!] Graylog Inputs with Secret Keys or Passwords")
    elif op == 6:
        print(Fore.RED + Style.NORMAL + "[!] Error obtaining Graylog Inputs")
    elif op == 7:
        print(Fore.RED + Style.NORMAL + "[!] Mongo DB without Authentication")
        print(Fore.GREEN + Style.NORMAL + SEPARATOR + Style.RESET_ALL)
        print(Fore.GREEN + Style.NORMAL + "[!] LDAP Settings")
    elif op == 8:
        print(Fore.GREEN + Style.NORMAL +
              "[!] LDAP Password Encrypted with AES CBC, Key is"
              " Graylog PasswordSecret and IV is the Salt")
    elif op == 9:
        print(Fore.GREEN + Style.NORMAL + "[!] AWS Access Key and Secret Key")
    elif op == 10:
        print(Fore.RED + Style.NORMAL +
              "[!] Problem with MongoDB Authentication")
    elif op == 11:
        print(Fore.RED + Style.NORMAL +
              "[!] MongoDB port is closed or unreachable")
    elif op == 12:
        print(Fore.GREEN + Style.NORMAL +
              "[!] Graylog Web Interface Default Credentials Found!")
    elif op == 13:
        print(Fore.RED + Style.NORMAL +
              "[!] Graylog Web Interface Default Credentials"
              " Not Found, Try Bruteforce Module")
    elif op == 14:
        print(Fore.GREEN + Style.NORMAL +
              "[!] Graylog SSH Default Credentials Found!")
    elif op == 15:
        print(Fore.RED + Style.NORMAL +
              "[!] Graylog SSH Default Credentials Not Found")

    print(Fore.GREEN + Style.NORMAL + SEPARATOR + Style.RESET_ALL)


def qradar_messages(op, message=''):
    print(Fore.GREEN + Style.NORMAL + SEPARATOR)
    if op == 1:
        print(Fore.RED + Style.BRIGHT +
              "[*] Error with number entered for quantity apikey")
    elif op == 2:
        print("[!] API Key: " + Fore.RED + Style.BRIGHT + message)
    elif op == 3:
        print(Fore.GREEN + Style.NORMAL + "[!] System information of QRadar :")
    elif op == 4:
        print(Fore.GREEN + Style.NORMAL + "[!] Users of QRadar :")
    elif op == 5:
        print(Fore.GREEN + Style.NORMAL +
              "[!] Networks configured in QRadar :")
    elif op == 6:
        print(Fore.GREEN + Style.NORMAL +
              "[!] Query of usernames AQL was Successful!")
    elif op == 7:
        print(Fore.RED + Style.NORMAL +
              "[!] Query of usernames AQL wasn't Successful!")

    print(Fore.GREEN + Style.NORMAL + SEPARATOR + Style.RESET_ALL)


def mcafee_messages(op):
    print(Fore.GREEN + Style.NORMAL + SEPARATOR)
    if op == 1:
        print(Fore.GREEN + Style.NORMAL + "[!] System information of McAfee :")
    elif op == 2:
        print(Fore.GREEN + Style.BRIGHT + "[*] Users McAfee server:")

    print(Fore.GREEN + Style.NORMAL + SEPARATOR + Style.RESET_ALL)


def smonster_messages(op):
    print(Fore.GREEN + Style.NORMAL + SEPARATOR)
    if op == 1:
        print(Fore.GREEN + Style.NORMAL +
              "[!] System information of SIEMonster :")
    elif op == 2:
        print(Fore.GREEN + Style.BRIGHT + "[*] Users SIEMonter Server:")

    print(Fore.GREEN + Style.NORMAL + SEPARATOR + Style.RESET_ALL)


def elastic_messages(op):
    if op == 1:
        print(Fore.GREEN + Style.NORMAL +
              "[!] System information of ElasticSIEM: ")

    print(Fore.GREEN + Style.NORMAL + SEPARATOR + Style.RESET_ALL)
