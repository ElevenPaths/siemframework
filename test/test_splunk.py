#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import requests_mock

from io import StringIO
from unittest.mock import patch

from splunk.testovacredentials import ova_credentials
from splunk.bruteforcesplunk import bruteforce_splunk


class TestSiemsframework(unittest.TestCase):

    def setUp(self):
        self.ip = '192.168.1.8'
        self.port = '8089'
        self.url_base = 'https://192.168.1.8:8089'
        self.stdout = 'sys.stdout'

    def test_bruteforce(self):
        result = "\n\n\x1b[32m\x1b[1m[*] =================================" \
                "========================================================" \
                "===================== [*]" \
                "\n\x1b[32m\x1b[1m[!] Dictionary Attack Successful!" \
                "\n\x1b[32m\x1b[1m[*] ====================================" \
                "=========================================================" \
                "================= [*]" \
                "\x1b[0m\n\n\n\x1b[32m\x1b[1m[*] =========================" \
                 "========================================================" \
                 "============================= [*]" \
                "\n\x1b[33m\x1b[1m[!] Username: \x1b[31m\x1b[1madmin" \
                "\n\x1b[33m[!] Password: \x1b[31m\x1b[1mno password" \
                "\n\x1b[32m\x1b[1m[*] ===================================" \
                "=========================================================" \
                "================== [*]\x1b[0m\n"

        with patch(self.stdout, new=StringIO()) as splunk_out:
            with patch('splunklib.client.connect') as mock_connect:
                mock_connect.return_value = True
                bruteforce_splunk(self.ip, self.port)
            self.assertEqual(splunk_out.getvalue(), result)

    @patch('paramiko.SSHClient.connect', return_value=True)
    def test_ssh_ova_credential(self, mock_ssh):
        user = 'root'
        password = 'changemenow'
        result = "\x1b[32m\x1b[22m[*] =================================" \
                 "========================================================" \
                 "===================== [*]" \
                 "\n\x1b[32m\x1b[22m[!] Splunk VMWare OVA SSH Default " \
                 "Credentials Found!" \
                 "\n\x1b[32m\x1b[22m[*] ====================================" \
                 "=========================================================" \
                 "================= [*]"\
                 "\x1b[0m\n\n\n\x1b[32m\x1b[1m[*] ============================" \
                 "=========================================================" \
                 "========================= [*]"\
                 "\n\x1b[33m\x1b[1m[!] Username: \x1b[31m\x1b[1mroot" \
                 "\n\x1b[33m[!] Password: \x1b[31m\x1b[1mchangemenow" \
                 "\n\x1b[32m\x1b[1m[*] ===================================" \
                 "=========================================================" \
                 "================== [*]\x1b[0m\n"

        with patch('sys.stdout', new=StringIO()) as splunk_out:
            ova_credentials(self.ip, user, password)
            self.assertEqual(splunk_out.getvalue(), result)


if __name__ == "__main__":
    unittest.main()

# %%%%%%%%%% The End %%%%%%%%%%#


