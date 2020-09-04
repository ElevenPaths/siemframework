#!/usr/bin/env python3

# Obtain system info of McAfee with SSH

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import globals
import paramiko

from colorama import Fore
from colorama import Style


# %%%%%%%%%% Functions %%%%%%%%%#


def mcafee_ssh_info(ip):
    password = input(Fore.CYAN + Style.NORMAL +
                     "[!] Enter McAfee root's password: " + Style.RESET_ALL)

    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, username='root', password=password,
                    banner_timeout=200)
        globals.mcafee_messages(1)

        commands = [
            ("hostname", "[!] Hostname"),
            ("chkconfig --list | grep \'5:on\' | awk \'{print $1}\'",
             "[!] Active Service"),
            ("ifconfig", "[!] Network Configuration"),
            ("iptables -nL", "[!] FW Configuration")
        ]

        for command in commands:
            std, stdout, stderr = ssh.exec_command(command[0])
            if stdout != "":
                print(Fore.GREEN + Style.NORMAL + command[1])
                print(Fore.GREEN + Style.NORMAL + globals.SEPARATOR
                      + Style.RESET_ALL)
                for i in stdout.readlines():
                    print('[!]  ' + i.replace('\n', ''))

        ssh.close()

    except paramiko.AuthenticationException:
        globals.messages(10)
        ssh.close()

# %%%%%%%%%% The End %%%%%%%%%%#
