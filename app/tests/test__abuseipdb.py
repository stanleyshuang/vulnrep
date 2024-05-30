# -*- coding: utf-8 -*-
#
# Author:   Stanley Huang
# Project:  honey ver. 1.0
# Date:     2022/03/19
#
import unittest
from pkg._abuseipdb import abuseipdb

class AbuseipdbTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass
    
    def test_abuseipdb_10(self):
        the_abuseipdb = abuseipdb()
        '''
        sample code:
        decoded_response = abuseipdb.check('45.148.10.59')
        print('decoded_response' + str(decoded_response))
        decoded_response{'data': {'ipAddress': '45.148.10.59', 'isPublic': True, 'ipVersion': 4, 'isWhitelisted': False, 'abuseConfidenceScore': 100, 'countryCode': 'RO', 'usageType': 'Data Center/Web Hosting/Transit', 'isp': 'Pptechnology Limited', 'domain': 'dmzhost.co', 'hostnames': ['edc11.app-autht.com'], 'totalReports': 534, 'numDistinctUsers': 115, 'lastReportedAt': '2022-03-19T06:56:21+00:00'}}
        '''

        decoded_response = {
            "data": {
                "abuseConfidenceScore": 100,
                "countryCode": "RO",
                "domain": "dmzhost.co",
                "hostnames": [
                    "edc11.app-autht.com"
                ],
                "ipAddress": "45.148.10.59",
                "ipVersion": 4,
                "isPublic": True,
                "isWhitelisted": False,
                "isp": "Pptechnology Limited",
                "lastReportedAt": "2022-03-19T06:56:21+00:00",
                "numDistinctUsers": 115,
                "totalReports": 534,
                "usageType": "Data Center/Web Hosting/Transit"
            }
        }
        b_is_bad, ip_addr = the_abuseipdb.is_black_ip(decoded_response)
        self.assertTrue(b_is_bad==True and ip_addr=='45.148.10.59')
    