#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   StanleyS Huang
# Project:  gsheet_incident_summary 1.0
# Date:     2021-12-04
#
import json, os
import time
from pkg._gsheet import i_gsheet

class gsheet_incident_summary(i_gsheet):
    '''
    Jira
    '''
    def __init__(self, the_credential, the_key, url):
        super(gsheet_incident_summary, self).__init__(the_credential, the_key, url)
        self.b_personal_data_collected = False
        self.timestamp = time.time()

    def update_cell(self, worksheet_name, mantis_id, col, value):
        worksheet = self.get_sheet(worksheet_name)

        recs = self.search_records_1(1, str(mantis_id), worksheet)
        if len(recs)==0:
            worksheet.append_row([str(mantis_id)])
        recs = self.search_records_1(1, str(mantis_id), worksheet)
        # print('  Update {row}, {col}, {value}'.format(row=recs[0][0], col=str(col), value=value))
        worksheet.update_cell(recs[0][0], col, value)

    def update_row(self, worksheet_name, mantis_id, row):
        worksheet = self.get_sheet(worksheet_name)

        recs = self.search_records_1(1, str(mantis_id), worksheet)
        if len(recs)==0:
            print('  append {id}'.format(id=str(mantis_id)))
            worksheet.append_row(row)
        elif len(recs)==1:
            merged = i_gsheet.merge_rec(recs[0][1], row)
            col=self.cal_col_by_len(len(merged))
            print('  merge {id} row:{row} col:{col} length:{len}'.format(id=str(mantis_id), row=str(recs[0][0]), col=col, len=len(merged)))
            worksheet.update('A{row}:{col}{row}'.format(row=recs[0][0], col=col), [merged])
        else:
            print('  skip {id}'.format(id=str(mantis_id)))
            pass