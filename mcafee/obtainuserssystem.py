#!/usr/bin/env python3

# Obtain system info of McAfee with SSH

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import globals
import paramiko
from colorama import Fore
from colorama import Style

# %%%%%%%%%% Functions %%%%%%%%%#


def mcafee_users_server(ip):
    password = input(
        Fore.CYAN + Style.NORMAL + "[!] Enter McAfee root's password: "
        + Style.RESET_ALL)

    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, username='root', password=password,
                    banner_timeout=200)
        sftp = ssh.open_sftp()
        shadow_file = sftp.open('/etc/shadow')
        globals.mcafee_messages(2)
        for line in shadow_file:
            print('[!] ' + line.replace('\n', ''))

        shadow_file.close()
        ssh.close()

    except paramiko.AuthenticationException:
        globals.messages(10)
        ssh.close()


# %%%%%%%%%% The End %%%%%%%%%%#
