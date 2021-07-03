# -*- coding: utf-8 -*-
#
# Author:   Stanley Huang
# Project:  vulnrep ver. 1.0
# Date:     2021/07/02
#
import unittest
from pkg.qjira.description import parse_severity_leve_in_summary
from pkg.qjira.description import severity_level_2_cvssv3_score

class ParseSeverityleveInSummaryTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass
    
    def test_parse_severity_leve_in_summary_10(self):
        self.assertTrue('[V3]'==parse_severity_leve_in_summary('[INTSI000-1023][Web][Security][Medium][V3] CSRF leads to change account settings of a victim (Mark Ella)'))

class SeverityLevel2Cvssv3ScoreTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass
    
    def test_severity_level_2_cvssv3_score_10(self):
        self.assertTrue('4.0', '6.9'==severity_level_2_cvssv3_score('[V3]'))

