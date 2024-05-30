# -*- coding: utf-8 -*-
#
# Author:   Stanley Huang
# Project:  util_datetime. 1.0
# Date:     2021/07/29
#
import unittest
from datetime import datetime
from pkg._util.util_datetime import utc_to_local_str

class UtcToLocalStrTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass
    
    def test_utc_to_local_str_10(self):
        local_str = utc_to_local_str(datetime(2021, 7, 29, 0, 0, 0), local_tz_str='Asia/Taipei', format='%Y-%m-%dT%H:%M:%S.000+0800')
        self.assertTrue('2021-07-29T08:00:00.000+0800'==local_str)
    
    def test_utc_to_local_str_20(self):
        local_str = utc_to_local_str(datetime(2021, 7, 29, 0, 0, 0), local_tz_str='GMT', format='%Y-%m-%dT%H:%M:%S.000+0000')
        self.assertTrue('2021-07-29T00:00:00.000+0000'==local_str)

