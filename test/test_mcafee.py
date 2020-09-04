#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import requests_mock

from io import StringIO
from unittest.mock import patch

from mcafee.bruteforcemcafee import mcafee_brute
from mcafee.bruteforcessh import mcafee_ssh_brute


class TestSiemsframework(unittest.TestCase):

    def setUp(self):
        self.ip = '192.168.1.8'
        self.port = '443'
        self.url_base = 'https://192.168.1.8:443'
        self.stdout = 'sys.stdout'
        self.headers = {
            'Accept': 'application/json,text/plain,*/*',
            'DNT': '1',
            'Host': self.ip,
            'Origin': self.url_base,
            'Referer': self.url_base,
            'Content-Type': 'application/json;charset=utf-8',
            'Connection': 'keep - alive',
            'X-Xsrf-Token': 'null'
        }

    @requests_mock.mock()
    def test_mcafee_brute(self, response):
        url1 = self.url_base + '/ess'
        url2 = self.url_base + '/rs/esm/v2/login'

        response.post(url1, status_code=200)
        response.post(url2, status_code=201)

        result = "\n\n\x1b[32m\x1b[1m[*] =================================" \
                 "========================================================" \
                 "===================== [*]" \
                 "\n\x1b[32m\x1b[1m[!] Dictionary Attack Successful!" \
                 "\n\x1b[32m\x1b[1m[*] ====================================" \
                 "=========================================================" \
                 "================= [*]"\
                 "\x1b[0m\n\n\n\x1b[32m\x1b[1m[*] ========================" \
                 "=========================================================" \
                 "============================= [*]"\
                 "\n\x1b[33m\x1b[1m[!] Username: \x1b[31m\x1b[1mNGCP" \
                 "\n\x1b[33m[!] Password: \x1b[31m\x1b[1mhs+&8:fiY91" \
                 "\n\x1b[32m\x1b[1m[*] ===================================" \
                 "=========================================================" \
                 "================== [*]\x1b[0m\n"

        with patch(self.stdout, new=StringIO()) as mcafee_out:
            mcafee_brute(self.ip, self.port)
            self.assertEqual(mcafee_out.getvalue(), result)

    def test_mcafee_ssh_brute(self):
        nm = {
            'nmap': {
                'command_line': 'nmap -oX - -sT -T4 -p 22 192.168.1.8',
                'scaninfo': {
                    'tcp': {
                        'method': 'connect', 'services': '22'}},
                'scanstats': {
                    'timestr': 'Sat May 16 17:00:54 2020',
                    'elapsed': '0.03', 'uphosts': '1', 'downhosts': '0','totalhosts': '1'}
            },
            'scan': {
                '192.168.1.8': {
                    'hostnames': [{'name': '', 'type': ''}],
                    'addresses': {
                        'ipv4': '192.168.1.8'},
                    'vendor': {},
                    'status': {
                        'state': 'up',
                        'reason': 'syn-ack'},
                    'tcp': {
                        22: {
                            'state': 'open',
                            'reason': 'syn-ack',
                            'name': 'ssh',
                            'product': '',
                            'version': '',
                            'extrainfo': '',
                            'conf': '3',
                            'cpe': ''}}}}}
        result = "\n\n\x1b[32m\x1b[1m[*] =================================" \
                 "========================================================" \
                 "===================== [*]" \
                 "\n\x1b[31m\x1b[1m[!] Dictionary Attack Not Successful" \
                 "\n\x1b[32m\x1b[1m[*] ====================================" \
                 "========================================================" \
                 "================== [*]\x1b[0m\n"

        with patch('sys.stdout', new=StringIO()) as mcafee_out:
            with patch('nmap.PortScanner.scan') as mock_nmap:
                with patch('paramiko.SSHClient.connect', autospec=True) as\
                        mock_ssh:
                    mock_nmap.return_value = nm
                    mock_nmap._scan_result = nm
                    mock_ssh.return_value = True
                    mcafee_ssh_brute(self.ip)
            self.assertEqual(mcafee_out.getvalue(), result)


if __name__ == "__main__":
    unittest.main()

# %%%%%%%%%% The End %%%%%%%%%%#


