# -*- coding: utf-8 -*-
#
# Author:   Stanley Huang
# Project:  vulnrep ver. 2.0
# Date:     2022/04/16
#
import unittest
from pkg._fdb.analysis import analysis, analysisException

class AnalysisUpdateCveidSeveritySummaryTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass
    
    def test_analysis_update_cveid_severity_summary_10(self):
        the_analysis = analysis(None, None, filename=None)
        the_analysis.json_obj = {}
        self.assertRaises(analysisException, the_analysis.update_cveid_severity_summary, '[Mantis#91217][ODM][Security][V3][Medium] ELECOM FW4.3.6.1300 資安問題確認 JVNVU#99602154 - CVE-2022-22721 | CVE-2022-23943', None, None, None)
    
    def test_analysis_update_cveid_severity_summary_20(self):
        the_analysis = analysis(None, None, filename=None)
        the_analysis.json_obj = {}
        the_analysis.update_cveid_severity_summary('[Mantis#91217][ODM][Security][V3][Medium] ELECOM FW4.3.6.1300 資安問題確認 JVNVU#99602154 (3rd-party) - CVE-2022-22721 | CVE-2022-23943', None, None, None)
        json_obj = the_analysis.get()
        self.assertTrue('CVE-2022-22721|CVE-2022-23943'==json_obj['cveid'] and 
                        '[V3]'==json_obj['severity_level'])

