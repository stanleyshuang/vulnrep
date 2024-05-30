#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   StanleyS Huang
# Project:  gsheet_opensrc 1.0
# Date:     2021-09-25
#
import json, os
import time
from pkg._gsheet import i_gsheet

class gsheet_opensrc(i_gsheet):
    '''
    Jira
    '''
    def __init__(self, the_credential, the_key, url):
        super(gsheet_opensrc, self).__init__(the_credential, the_key, url)
        self.b_personal_data_collected = False
        self.timestamp = time.time()

    def sleep(self, b_enforced=False):
        now = time.time()
        difference = int(now - self.timestamp)
        if b_enforced:
            time.sleep(1)
        if difference>=1:
            time.sleep(2.33)
            self.timestamp = time.time()

    def update_global_table(self, row):
        self.sleep()
        worksheet_name = 'Global'
        worksheet = self.get_sheet(worksheet_name)

        recs = self.search_records_n({2: row[1], 3: row[2], 4: row[3], 5: row[4]}, worksheet_name)
        if len(recs)==0:
            print('  Update Global table {row}'.format(row=str(row)))
            worksheet.append_row(row)
        elif len(recs)==1:
            merged = i_gsheet.merge_rec(recs[0][1], row)
            worksheet.update('A{row}:{col}{row}'.format(row=recs[0][0], col=self.cal_col_by_len(len(merged))), [merged])
        else:
            pass
