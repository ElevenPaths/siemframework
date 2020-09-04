#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import scanning
import requests_mock

from unittest.mock import patch


class TestSIEMFramework(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        self.ip = '192.168.1.8'
        self.port = '443'
        self.inputs = 'builtins.input'
        self.url_base ='https://192.168.1.8:443'

    def test_input_ip(self):
        result_true = '10.1.16.200'
        result_false = ''
        with patch(self.inputs, return_value='10.1.16.200'):
            ip_true = scanning.input_ip()
        self.assertEqual(ip_true, result_true)

        with patch(self.inputs, return_value='1000.1.10.300'):
            ip_false = scanning.input_ip()
        self.assertEqual(ip_false, result_false)

    def test_input_port(self):
        result_default = 0
        result_true = '8888'
        result_false = ''
        with patch(self.inputs, return_value=''):
            port_default = scanning.input_port()
        self.assertEqual(port_default, result_default)

        with patch(self.inputs, return_value='8888'):
            port_true = scanning.input_port()
        self.assertEqual(port_true, result_true)

        with patch(self.inputs, return_value='1000110300'):
            port_false = scanning.input_ip()
        self.assertEqual(port_false, result_false)

    def test_input_net(self):
        result = '192.168.1.0/24'
        with patch(self.inputs, return_value='192.168.1.0/24'):
            net = scanning.input_net()
        self.assertEqual(net, result)

    @requests_mock.mock()
    def test_splunk_detect(self, response):
        self.port = '8089'
        response.get('https://192.168.1.8:8089', text='splunkd')
        result = 'Splunk'
        self.assertEqual(scanning.splunk_detect(self.ip, self.port), result)

    @requests_mock.mock()
    def test_graylog_detect(self, response):
        self.port = '9000'
        response.get('http://192.168.1.8:9000', text='Graylog Web Interface')
        result = 'Graylog'
        self.assertEqual(scanning.graylog_detect(self.ip, self.port), result)

    @requests_mock.mock()
    def test_ossim_detect(self, response):
        response.get(self.url_base + '/ossim/session/login.php',
                     text='AlienVault OSSIM')
        result = 'OSSIM'
        self.assertEqual(scanning.ossim_detect(self.ip, self.port), result)

    @requests_mock.mock()
    def test_qradar_detect(self, response):
        response.get(self.url_base + '/console/', headers={'Server': 'QRadar'})
        result = 'QRadar'
        self.assertEqual(scanning.qradar_detect(self.ip, self.port), result)

    @requests_mock.mock()
    def test_mcafee_detect(self, response):
        response.get(self.url_base, text='McAfee SIEM')
        result = 'McAfee'
        self.assertEqual(scanning.mcafee_detect(self.ip, self.port), result)

    @requests_mock.mock()
    def test_elasticsiem_detect(self, response):
        self.port = '5601'
        response.get('http://192.168.1.8:5601' + '/app/siem',
                     headers={'kbn-name': 'elasticsiem'}, text='Elastic')
        result = 'ElasticSIEM'
        self.assertEqual(scanning.elasticsiem_detect(self.ip, self.port),
                         result)

    def test_scan_host(self):
        result = 'None'
        self.assertEqual(scanning.scan_host(self.ip, self.port), result)


if __name__ == "__main__":
    unittest.main()

# %%%%%%%%%% The End %%%%%%%%%%#


