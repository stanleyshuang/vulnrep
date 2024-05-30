# -*- coding: utf-8 -*-
#
# Author:   Stanley Huang
# Project:  vulnrep ver. 1.0
# Date:     2021/06/27
#
import unittest
from pkg._cve import cve

class CveJsonTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass
    
    def test_is_cve_json_filename_10(self):
        self.assertTrue(cve.is_cve_json_filename('CVE-2021-28809.json'))
    
    def test_is_cve_json_filename_11(self):
        self.assertFalse(cve.is_cve_json_filename('CVE-2021-28809.x.json'))
    
    def test_is_cve_json_filename_20(self):
        self.assertTrue(cve.is_cve_json_filename('CVE-2021-3660.json'))
    
    def test_is_cve_json_filename_21(self):
        self.assertFalse(cve.is_cve_json_filename('CVE-2021-3660.x.json'))
    
    def test_is_cve_json_filename_30(self):
        self.assertFalse(cve.is_cve_json_filename('CVE-2021-3660.txt'))
    
    def test_is_cve_json_filename_40(self):
        self.assertFalse(cve.is_cve_json_filename('openpgp-encrypted-message'))

class CveJsonXTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass
    
    def test_is_cve_x_json_filename_10(self):
        self.assertTrue(cve.is_cve_x_json_filename('CVE-2021-28809.x.json'))
    
    def test_is_cve_x_json_filename_11(self):
        self.assertFalse(cve.is_cve_x_json_filename('CVE-2021-28809.json'))
    
    def test_is_cve_x_json_filename_12(self):
        self.assertTrue(cve.is_cve_x_json_filename('CVE-2021-28809.x.x.json'))
    
    def test_is_cve_x_json_filename_20(self):
        self.assertTrue(cve.is_cve_x_json_filename('CVE-2021-3660.x.json'))
    
    def test_is_cve_x_json_filename_21(self):
        self.assertFalse(cve.is_cve_x_json_filename('CVE-2021-3660.json'))
    
    def test_is_cve_x_json_filename_22(self):
        self.assertTrue(cve.is_cve_x_json_filename('CVE-2021-3660.x.x.json'))
    
    def test_is_cve_x_json_filename_30(self):
        self.assertFalse(cve.is_cve_x_json_filename('CVE-2021-3660.x.txt'))
    
    def test_is_cve_x_json_filename_40(self):
        self.assertFalse(cve.is_cve_x_json_filename('openpgp-encrypted-message'))
        