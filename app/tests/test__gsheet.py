# -*- coding: utf-8 -*-
#
# Author:   Stanley Huang
# Project:  vulnrep ver. 1.0
# Date:     2023/03/06
#
import os
import unittest
from pkg._gsheet import i_gsheet
from pkg._gsheet.gsheet_vulnrep import gsheet_vulnrep

class GSheetTestCase(unittest.TestCase):
    def setUp(self):
        google_sheet_key = os.environ.get('google_sheet_key')
        google_api_credential = os.environ.get('google_api_credential')
        self.gsheet = gsheet_vulnrep(the_credential=google_api_credential, 
                                     the_key=google_sheet_key, 
                                     url=os.environ.get('jira_url'))

    def tearDown(self):
        pass
    
    def test_merge_rec_10(self):
        self.assertTrue(i_gsheet.merge_rec(['0', None, '2'], [None, '1'])==['0', '1', '2'])
    
    def test_merge_rec_20(self):
        self.assertTrue(i_gsheet.merge_rec(['0', '', '2'], [None, '1'])==['0', '1', '2'])
    
    def test_merge_rec_30(self):
        self.assertTrue(i_gsheet.merge_rec(['0', '', '2'], ['new 0', '1'], no_overwrite_idxs=[0, 1])==['0', '1', '2'])
    
    def test_merge_rec_40(self):
        self.assertTrue(i_gsheet.merge_rec(['0', '', '2'], ['new 0', '1'])==['new 0', '1', '2'])
    
    def test_merge_rec_50(self):
        self.assertTrue(i_gsheet.merge_rec(['0', ''], ['new 0', '1', '2'], no_overwrite_idxs=[0, 1])==['0', '1', '2'])
    
    def test_merge_rec_60(self):
        self.assertTrue(i_gsheet.merge_rec(['0', ''], ['new 0', '1', '2'])==['new 0', '1', '2'])
    
    def test_available_qsa_id_10(self):
        qsaid = self.gsheet.available_qsa_id()
        print('可使用 QSA ID 為 ' + qsaid)
        self.assertTrue(True)