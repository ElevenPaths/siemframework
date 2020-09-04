#!/usr/bin/env python3

# Obtain system info of SIEMonster with SSH

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import globals
import paramiko
from colorama import Fore
from colorama import Style

# %%%%%%%%%%% Constants %%%%%%%%%%%#

SEPARATOR = "[*] {0} [*]".format('=' * 110)

# %%%%%%%%%% Functions %%%%%%%%%#


def smonster_ssh_info(ip):
    password = input(
        Fore.CYAN + Style.NORMAL + "[!] Enter SIEMonster deploy's password: "
        + Style.RESET_ALL)

    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, username='deploy', password=password,
                    banner_timeout=200)
        globals.smonster_messages(1)

        commands = [
            ("hostname", "[!] Hostname"),
            ("docker ps --format \"table {{.Names}}\t{{.Ports}}\t"
             "{{.Status}}\"", "[!] Active Containers"),
            ("ls -1  /etc/rc5.d", "[!] List service active"),
            ("ifconfig", "[!] Network Configuration"),
            ("sudo iptables -nL", "[!] FW Configuration")
        ]

        for command in commands:
            stdin, stdout, stderr = ssh.exec_command(command[0])
            if stdout != "":
                print('')
                print(Fore.GREEN + Style.NORMAL + command[1])
                print(Fore.GREEN + Style.NORMAL + SEPARATOR + Style.RESET_ALL)
                for i in stdout.readlines():
                    print('[!]  ' + i.replace('\n', ''))

    except paramiko.AuthenticationException:
        globals.messages(10)
        ssh.close()

# %%%%%%%%%% The End %%%%%%%%%%#
