#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import requests_mock

from io import StringIO
from unittest.mock import patch

from ossim.bruteforceossim import ossim_brute


class TestSiemsframework(unittest.TestCase):

    def setUp(self):
        self.ip = '192.168.1.8'
        self.port = '443'
        self.url_base = 'https://192.168.1.8:443'
        self.stdout = 'sys.stdout'

    @requests_mock.mock()
    def test_ossim_brute(self, response):
        url = self.url_base + "/ossim/session/login.php"
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
                 "\n\x1b[33m\x1b[1m[!] Username: \x1b[31m\x1b[1madmin" \
                 "\n\x1b[33m[!] Password: \x1b[31m\x1b[1mossim" \
                 "\n\x1b[32m\x1b[1m[*] ===================================" \
                 "=========================================================" \
                 "================== [*]\x1b[0m\n"

        response.post(url, status_code=302)
        with patch(self.stdout, new=StringIO()) as ossim_out:
            ossim_brute(self.ip, self.port)
            self.assertEqual(ossim_out.getvalue(), result)


if __name__ == "__main__":
    unittest.main()

# %%%%%%%%%% The End %%%%%%%%%%#


