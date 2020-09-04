#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

import siemsframework
from unittest.mock import call
from unittest.mock import patch


class TestSiemsframework (unittest.TestCase):
    inputs = 'siemsframework.input'

    def setUp(self):
        self.inputs = 'siemsframework.input'
        self.options = ['Splunk', 'Graylog', 'OSSIM', 'QRadar', 'McAfee']

    def test_menus_options(self):
        for option in self.options:
            with patch(self.inputs, return_value=option):
                value_expect = option
                return_value = siemsframework.menus(menu=option)

        self.assertEqual(value_expect, return_value)

    @unittest.mock.patch(inputs, return_value='1')
    def test_menus_option_1(self, mock):
        value_expect = '1'
        return_value = siemsframework.menus(menu=1)

        self.assertEqual(value_expect, return_value)
        self.assertEqual(mock.call_count, 1)

    @unittest.mock.patch(inputs, return_value='2')
    def test_menus_option_2(self, mock):
        value_expect = '2'
        return_value = siemsframework.menus(menu=2)

        self.assertEqual(value_expect, return_value)
        self.assertEqual(mock.call_count, 1)


if __name__ == "__main__":
    unittest.main()