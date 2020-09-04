#!/usr/bin/env python3

# Obtain system info of ElasticSIEM with SSH

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import globals
import paramiko
from colorama import Fore
from colorama import Style

# %%%%%%%%%% Functions %%%%%%%%%#


def elastic_ssh_info(ip):
    username = input(Fore.CYAN + Style.NORMAL +
                     "[!] Enter ElasticSIEM's username: " + Style.RESET_ALL)
    password = input(Fore.CYAN + Style.NORMAL +
                     "[!] Enter ElasticSIEM's password: " + Style.RESET_ALL)

    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, username=username, password=password,
                    banner_timeout=200)
        globals.elastic_messages(1)

        commands = [
            ("hostname", "[!] Hostname"),
            ("ls -1  /etc/rc5.d", "[!] List service active"),
            ("ifconfig", "[!] Network Configuration"),
            ('netstat -putan | grep LISTEN', "[!] Ports active")
            ]

        for command in commands:
            std, stdout, stderr = ssh.exec_command(command[0])
            if stdout != "":
                print('')
                print(Fore.GREEN + Style.NORMAL + command[1])
                print(Fore.GREEN + Style.NORMAL + globals.SEPARATOR +
                      Style.RESET_ALL)
                for i in stdout.readlines():
                    print('[!]  ' + i.replace('\n', ''))

        ssh.close()

    except paramiko.AuthenticationException:
        globals.messages(10)
        ssh.close()

# %%%%%%%%%% The End %%%%%%%%%%#
