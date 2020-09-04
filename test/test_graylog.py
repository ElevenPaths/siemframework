#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import requests_mock

from io import StringIO
from unittest.mock import patch
from graylog.bruteforcegraylog import graylog_brute
from graylog.testcredentialsgraylog import default_web_credentials
from graylog.testcredentialsgraylog import default_ssh_credentials
from graylog.obtaincredentialsrestapi import obtain_ldap_credentials


class TestSiemsframework(unittest.TestCase):

    def setUp(self):
        self.ip = '192.168.1.8'
        self.port = '9000'
        self.url_base = 'http://192.168.1.8:9000'
        self.stdout = 'sys.stdout'

    @requests_mock.mock()
    def test_graylog_brute(self, response):
        url = self.url_base + "/api/system/sessions"
        result = "\n\n\x1b[32m\x1b[1m[*] ==================================" \
                 "=========================================================" \
                 "=================== [*]" \
                 "\n\x1b[32m\x1b[1m[!] Dictionary Attack Successful!" \
                 "\n\x1b[32m\x1b[1m[*] ====================================" \
                 "=========================================================" \
                 "================= [*]"\
                 "\x1b[0m\n\n\n\x1b[32m\x1b[1m[*] =========================" \
                 "=========================================================" \
                 "============================ [*]"\
                 "\n\x1b[33m\x1b[1m[!] Username: \x1b[31m\x1b[1madmin" \
                 "\n\x1b[33m[!] Password: \x1b[31m\x1b[1madmin" \
                 "\n\x1b[32m\x1b[1m[*] ====================================" \
                 "==========================================================" \
                 "================ [*]\x1b[0m\n"

        response.post(url, status_code=200)
        with patch(self.stdout, new=StringIO()) as graylog_out:
            graylog_brute(self.ip, self.port)
            self.assertEqual(graylog_out.getvalue(), result)

    @requests_mock.mock()
    def test_web_credentials(self, response):
        url = self.url_base + "/api/system/sessions"
        result = "\x1b[32m\x1b[22m[*] ======================================" \
                 "==========================================================" \
                 "============== [*]" \
                 "\n\x1b[32m\x1b[22m[!] Graylog Web Interface Default " \
                 "Credentials Found!" \
                 "\n\x1b[32m\x1b[22m[*] ===================================" \
                 "==========================================================" \
                 "================= [*]" \
                 "\x1b[0m\n\n\n\x1b[32m\x1b[1m[*] ========================" \
                 "=========================================================" \
                 "============================= [*]" \
                 "\n\x1b[33m\x1b[1m[!] Username: \x1b[31m\x1b[1madmin" \
                 "\n\x1b[33m[!] Password: \x1b[31m\x1b[1madmin" \
                 "\n\x1b[32m\x1b[1m[*] ===================================" \
                 "=========================================================" \
                 "================== [*]\x1b[0m\n"

        response.post(url, status_code=200)
        with patch(self.stdout, new=StringIO()) as graylog_out:
            default_web_credentials(self.ip, self.port)
            self.assertEqual(graylog_out.getvalue(), result)

    def test_ssh_credentials(self):
        result = "\x1b[32m\x1b[22m[*] ====================================" \
                 "========================================================" \
                 "================== [*]" \
                 "\n\x1b[32m\x1b[22m[!] Graylog SSH Default Credentials " \
                 "Found!" \
                 "\n\x1b[32m\x1b[22m[*] ==================================" \
                 "========================================================" \
                 "==================== [*]" \
                 "\x1b[0m\n\n\n\x1b[32m\x1b[1m[*] =======================" \
                 "========================================================" \
                 "=============================== [*]" \
                 "\n\x1b[33m\x1b[1m[!] Username: \x1b[31m\x1b[1mubuntu" \
                 "\n\x1b[33m[!] Password: \x1b[31m\x1b[1mubuntu" \
                 "\n\x1b[32m\x1b[1m[*] ===================================" \
                 "=========================================================" \
                 "================== [*]\x1b[0m\n"

        with patch('sys.stdout', new=StringIO()) as graylog_out,\
                patch('paramiko.SSHClient.connect', autospec=True) as mock_ssh:
            mock_ssh.return_value = True
            default_ssh_credentials(self.ip)
            self.assertEqual(graylog_out.getvalue(), result)

    @requests_mock.mock()
    def test_credentials_restapi(self, response):
        urlldap = self.url_base + "/api/system/ldap/settings?pretty=true"
        urlaws = self.url_base + "/api/system/cluster_config/" \
                                 "org.graylog.aws.config." \
                                 "AWSPluginConfiguration?pretty=true"
        ldap = '\n "enable" : true,' \
               '\n "system_username" : "uid=pruebaldap, ou=system",' \
               '\n "system_password": "pruebaldap"'
        aws = '\n "lookups_enable" : false,' \
              '\n "access_key" : "ALIMAYELELLAV7IDEA",' \
              '\n "secret_key": "ElevenPaths/LABORATORY/Latam"'

        result = "\x1b[32m\x1b[22m[*] ====================================" \
                 "========================================================" \
                 "================== [*]" \
                 "\n\x1b[32m\x1b[22m[!] Graylog LDAP Settings and Credentials" \
                 "\n\x1b[32m\x1b[22m[*] ====================================" \
                 "==========================================================" \
                 "================ [*]" \
                 "\x1b[0m\n\n[!] \"enable\" : true," \
                 "\n[!] \"system_username\" : \"uid=pruebaldap, ou=system\"," \
                 "\n[!] \"system_password\": \"pruebaldap\"" \
                 "\n\x1b[32m\x1b[22m[*] ===================================" \
                 "=========================================================" \
                 "================== [*]" \
                 "\n\x1b[32m\x1b[22m[!] Graylog AWS Settings and Credentials" \
                 "\n\x1b[32m\x1b[22m[*] ===================================" \
                 "=========================================================" \
                 "================== [*]" \
                 "\x1b[0m\n\n[!] \"lookups_enable\" : false," \
                 "\n[!] \"access_key\" : \"ALIMAYELELLAV7IDEA\"," \
                 "\n[!] \"secret_key\": \"ElevenPaths/LABORATORY/Latam\"\n"

        response.get(urlldap, status_code=200, text=ldap)
        response.get(urlaws, status_code=200, text=aws)
        with patch(self.stdout, new=StringIO()) as graylog_out:
            with patch('getpass.getpass', return_value='admin'):
                obtain_ldap_credentials(self.ip, self.port)
            self.assertEqual(graylog_out.getvalue(), result)


if __name__ == "__main__":
    unittest.main()

# %%%%%%%%%% The End %%%%%%%%%%#


