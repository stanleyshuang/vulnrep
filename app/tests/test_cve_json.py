# -*- coding: utf-8 -*-
#
# Author:   Stanley Huang
# Project:  vulnrep ver. 1.0
# Date:     2021/06/27
#
import unittest
from pkg.qjira.cve_json import is_cve_json_filename

class CveJsonTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass
    
    def test_is_cve_json_filename(self):
        self.assertTrue(is_cve_json_filename('CVE-2021-28809'))
    
    def test_is_cve_json_filename_2(self):
        self.assertTrue(is_cve_json_filename('CVE-2021-3660'))
    
    def test_is_cve_json_filename_3(self):
        self.assertFalse(is_cve_json_filename('CVE-2021-3660.json'))
    
    def test_is_cve_json_filename_4(self):
        self.assertFalse(is_cve_json_filename('openpgp-encrypted-message'))
        