#!/usr/bin/env python3

# Graylog Tes Default OVA/AMI Credentials Web: admin/admin SSH: ubuntu/ubuntu

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

import globals
import logging
import paramiko
import requests


# %%%%%%%%%% Functions %%%%%%%%%#


def default_web_credentials(ip, port):

    url = globals.http + ip + ":" + str(port) + "/api/system/sessions"
    # default web interface credentials
    params = {
        'username': 'admin',
        'password': 'admin',
        'host': ip
    }
    headers = {'X-Requested-By': 'XMLHttpRequest'}

    try:
        response = requests.post(url, json=params,
                                 headers=headers, verify=False)

        if response.status_code == 200:
            globals.graylog_messages(12)
            mess = ['admin', 'admin']
            globals.messages(9, mess)
        else:
            globals.graylog_messages(13)

    except Exception as e:
        logging.error(e, exc_info=True)


def default_ssh_credentials(ip):

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(ip, username='ubuntu', password='ubuntu')
        globals.graylog_messages(14)
        mess = ['ubuntu', 'ubuntu']
        globals.messages(9, mess)
    except paramiko.AuthenticationException:
        globals.graylog_messages(15)

# %%%%%%%%%% The End %%%%%%%%%%#
