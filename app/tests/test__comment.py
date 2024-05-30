# -*- coding: utf-8 -*-
#
# Author:   Stanley Huang
# Project:  vulnrep ver. 1.0
# Date:     2021/07/02
#
import unittest
from pkg._qjira.comment import content_filter

class ContentFilterTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass
    
    def test_content_filter_10(self):
        self.assertTrue(content_filter(
            '[INTSI000-1023][Web][Security][Medium][V3] CSRF leads to change account settings of a victim (Mark Ella)',
            ['[Security]', ['[V1]', '[V2]', '[V3]', '[V4]', '[V5]']]))
    
    def test_content_filter_13(self):
        self.assertTrue(content_filter(
            '[INTSI000-1023][Web][Security][Medium][V3] CSRF leads to change account settings of a victim (Mark Ella)',
            [['[V1]', '[V2]', '[V3]', '[V4]', '[V5]'], '[Security]']))
    
    def test_content_filter_20(self):
        self.assertFalse(content_filter(
            '[INTSI000-1023][Web][Medium][V3] CSRF leads to change account settings of a victim (Mark Ella)',
            ['[Security]', ['[V1]', '[V2]', '[V3]', '[V4]', '[V5]']]))
    
    def test_content_filter_30(self):
        self.assertFalse(content_filter(
            '[INTSI000-1023][Web][V5][Medium][V3] CSRF leads to change account settings of a victim (Mark Ella)',
            ['[Security]', ['[V1]', '[V2]', '[V3]', '[V4]', '[V5]']]))
