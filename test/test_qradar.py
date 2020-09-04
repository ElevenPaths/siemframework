#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import requests_mock

from io import StringIO
from unittest.mock import patch

from qradar.bruteforceqradar import qradar_brute
from qradar.apikeybruteqradar import qradar_apikeybrute


class TestSiemsframework (unittest.TestCase):

    def setUp(self):
        self.inputs = 'siemsframework.input'
        self.ip = '192.168.1.8'
        self.port = '443'
        self.url_base = 'https://192.168.1.8:443'
        self.stdout = 'sys.stdout'

    @requests_mock.mock()
    def test_qradar_brute(self, session):
        url = self.url_base + '/console/'
        auth = self.url_base + "/console/j_security_check"
        headers = {
            'QRadarCSRF': 'null',
            'Set-Cookie': 'CSRF=8746737hy749; Max'
        }

        result = "\n\n\x1b[32m\x1b[1m[*] ==============================" \
                 "=======================================================" \
                 "========================= [*]" \
                 "\n\x1b[32m\x1b[1m[!] Dictionary Attack Successful!" \
                 "\n\x1b[32m\x1b[1m[*] ===================================" \
                 "========================================================" \
                 "=================== [*]" \
                 "\x1b[0m\n\n\n\x1b[32m\x1b[1m[*] ==========================" \
                 "========================================================" \
                 "============================ [*]" \
                 "\n\x1b[33m\x1b[1m[!] Username: \x1b[31m\x1b[1madmin" \
                 "\n\x1b[33m[!] Password: \x1b[31m\x1b[1mqradar" \
                 "\n\x1b[32m\x1b[1m[*] =================================" \
                 "========================================================" \
                 "===================== [*]\x1b[0m\n"

        session.get(url, headers=headers)
        session.post(auth, status_code=322)

        with patch(self.stdout, new=StringIO()) as qrbrute_out:
            qradar_brute(self.ip, self.port)
            self.assertEqual(qrbrute_out.getvalue(), result)

    @requests_mock.mock()
    def test_qradar_apikeybrute(self, response):
        url = self.url_base + "/api/system/servers"

        response.get(url, status_code=200)

        result = "\n\n\x1b[32m\x1b[1m[*] ===============================" \
                 "=======================================================" \
                 "======================== [*]" \
                 "\n\x1b[32m\x1b[1m[!] Dictionary Attack Successful!" \
                 "\n\x1b[32m\x1b[1m[*] =====================================" \
                 "==========================================================" \
                 "=============== [*]" \
                 "\x1b[0m\n\x1b[32m\x1b[22m[*] =============================" \
                 "==========================================================" \
                 "======================= [*]" \
                 "\n[!] API Key: \x1b[31m\x1b[1m784fba0a-784b-2d3d-a4ba" \
                 "-97f4cc1a7d70" \
                 "\n\x1b[32m\x1b[22m[*] ===================================" \
                 "=========================================================" \
                 "================== [*]\x1b[0m\n"

        with patch(self.stdout, new=StringIO()) as qradar_out:
            qradar_apikeybrute(self.ip, self.port)
            self.assertEqual(qradar_out.getvalue(), result)


if __name__ == "__main__":
    unittest.main()

# %%%%%%%%%% The End %%%%%%%%%%#


