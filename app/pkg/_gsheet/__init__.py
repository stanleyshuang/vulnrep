#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  gsheet 1.0
# Date:     2021-07-15
#
import abc
import gspread
import random
import time

from oauth2client.service_account import ServiceAccountCredentials

def gsheet_except_handler(func):
    def wrapper(*args, **kwargs):
        n = 0
        while True:
            try:
                return func(*args, **kwargs)
            except gspread.exceptions.APIError as e:
                postponed = int(min((2**n)*1000+random.randint(0,999), 64000)/1000)
                print('    sleep: [' + str(postponed) + '] sec.')
                time.sleep(postponed)
                n += 1
                continue
            except Exception as e:
                print('    ' + str(e))
            break
    return wrapper

@gsheet_except_handler
def open_by_key(obj, key, sheet):
    return obj.client.open_by_key(key).worksheet(sheet)

@gsheet_except_handler
def col_values(worksheet, key):
    return worksheet.col_values(key)

@gsheet_except_handler
def row_values(worksheet, key):
    return worksheet.row_values(key)

@gsheet_except_handler
def findall(worksheet, key):
    return worksheet.findall(key)

@gsheet_except_handler
def append_row(worksheet, key):
    worksheet.append_row(key)

@gsheet_except_handler
def update(worksheet, key, values):
    worksheet.update(key, values)

@gsheet_except_handler
def get_all_values(worksheet):
    return worksheet.get_all_values()

class i_gsheet():
    __metaclass__ = abc.ABCMeta
    
    def __init__(self, the_credential, the_key, url):
        scopes = ["https://spreadsheets.google.com/feeds"]
        credentials = ServiceAccountCredentials.from_json_keyfile_name(the_credential, scopes)
        self.client = gspread.authorize(credentials)
        self.the_key = the_key
        self.url = url

    def get_sheet(self, sheet='sheet1'):
        worksheet = open_by_key(self, self.the_key, sheet)
        return worksheet

    def search_records_1(self, key, value, worksheet):
        the_data = []
        cell_list = col_values(worksheet, key)
        rows = i_gsheet.single_col_match(value, cell_list)
        for row in rows:
            values_list = row_values(worksheet, row+1)
            the_data.append((row+1, values_list))
        return the_data

    def batch_search_records_1(self, key, values, worksheet):
        cell_list = col_values(worksheet, key)
        the_group = {}
        for value in values:
            rows = i_gsheet.single_col_match(value, cell_list)
            the_data = []
            for row in rows:
                values_list = row_values(worksheet, row+1)
                the_data.append((row+1, values_list))
            the_group[value] = the_data
        return the_group

    def search_records_n(self, filters, worksheet):
        '''
        filters: { col:value, ... }
        col: begin from 1, i.e. 1=='A', 2=='B', 3=='C', and so on
        '''
        the_data = []
        cell_lists = {} # { value: [cell, ...] }
        for col in filters:
            cell_lists[filters[col]] = findall(worksheet, filters[col])
        rows = i_gsheet.multi_col_match(filters, cell_lists)
        for row in rows:
            values_list = row_values(worksheet, row)
            the_data.append((row, values_list))
        return the_data

    @abc.abstractmethod
    def set(self, *args, **kwargs):
        print('Set', args, kwargs)

    def cal_col_by_len(self, col_len):
        if col_len>=104:
            return'D'+chr(ord('A')+col_len-104)
        if col_len>=78:
            return'C'+chr(ord('A')+col_len-78)
        if col_len>=52:
            return'B'+chr(ord('A')+col_len-52)
        if col_len>=26:
            return'A'+chr(ord('A')+col_len-26)
        return chr(ord('A')+col_len)

    @staticmethod
    def single_col_match(value, cell_list):
        # print('>>> find {value}'.format(value=value))
        rows = []
        for i in range(len(cell_list)):
            # print('>>> {value}: {row}'.format(value=cell_list[i], row=i))
            if cell_list[i]==value:
                rows.append(i)
        # print('>>> return ' + str(rows))
        return rows

    @staticmethod
    def multi_col_match(filters, cell_lists):
        '''
        filters: { col:value, ... }
        col: begin from 1, i.e. 1=='A', 2=='B', 3=='C', and so on
        cell_lists: { value: [cell, ...] }
        '''
        rows = []
        row2cols = {} # { row:set(col), ... }
        for col, value in filters.items():
            if value in cell_lists:
                cell_list = cell_lists[value]
                for cell in cell_list:
                    # print('>>> {value}: ({row}, {col})'.format(value=cell.value, row=cell.row, col=cell.col))
                    if cell.col==col:
                        if cell.row not in row2cols:
                            row2cols[cell.row] = set()
                        row2cols[cell.row].add(col)
        '''
        print('row2cols')
        for row in row2cols:
            for col in row2cols[row]:
                print('>>> ({row}, {col})'.format(row=row, col=col))
        '''
        for row in row2cols:
            if len(row2cols[row])==len(filters):
                rows.append(row)
        return rows

    @staticmethod
    def merge_rec(old, new, no_overwrite_idxs=None):
        merged = []
        if len(old) > len(new):
            maxlen = len(old)
            for i in range(len(old)):
                if i < len(new) and (new[i] and (type(new[i])!=str or len(new[i])>0)) and (no_overwrite_idxs is None or i not in no_overwrite_idxs or ((old[i] is None or (type(old[i])==str and len(old[i])==0)))):
                    merged.append(new[i])
                else:
                    merged.append(old[i])
        else:
            maxlen = len(new)
            for i in range(len(new)):
                if i < len(old) and ((new[i] is None or (type(new[i])==str and len(new[i])==0)) or (no_overwrite_idxs and i in no_overwrite_idxs and (old[i] and (type(old[i])!=str or len(old[i])>0)))):
                    merged.append(old[i])
                else:
                    merged.append(new[i])
        return merged

    def get_records(self, sheet='sheet1'):
        worksheet = self.get_sheet(sheet)
        lists = get_all_values(worksheet)
        return lists

    def search_n_update(self, key, value, the_rec, worksheet, no_overwrite_idxs=None):
        recs = self.search_records_1(key, value, worksheet)
        if len(recs)==0:
            append_row(worksheet, the_rec)
            return 0
        elif len(recs)==1:
            merged = i_gsheet.merge_rec(recs[0][1], the_rec, no_overwrite_idxs)
            update(worksheet, 'A{row}:{col}{row}'.format(row=recs[0][0], col=chr(ord('A')+len(merged))), [merged])
            return 1
        else:
            return 2

    def search_n_update_n(self, filters, the_rec, worksheet, no_overwrite_idxs=None):
        '''
        filters: { col:value, ... }
        col: begin from 1, i.e. 1=='A', 2=='B', 3=='C', and so on
        cell_lists: { value: [cell, ...] }
        '''
        recs = self.search_records_n(filters, worksheet)
        if len(recs)==0:
            append_row(worksheet, the_rec)
            return 0
        elif len(recs)==1:
            merged = i_gsheet.merge_rec(recs[0][1], the_rec, no_overwrite_idxs)
            update(worksheet, 'A{row}:{col}{row}'.format(row=recs[0][0], col=chr(ord('A')+len(merged))), [merged])
            return 1
        else:
            return 2

    def batch_search_n_update(self, idx, the_key_2_recs, worksheet, no_overwrite_idxs=None):
        num_founds = {}
        keys = list(the_key_2_recs.keys())
        the_group_recs = self.batch_search_records_1(idx, keys, worksheet)
        for key in the_group_recs:
            recs = the_group_recs[key]          
            if len(recs)==0:
                append_row(worksheet, the_key_2_recs[key])
                num_founds[key] = 0
            elif len(recs)==1:
                merged = i_gsheet.merge_rec(recs[0][1], the_key_2_recs[key], no_overwrite_idxs)
                update(worksheet, 'A{row}:{col}{row}'.format(row=recs[0][0], col=chr(ord('A')+len(merged))), [merged])
                num_founds[key] = 1
            else:
                num_founds[key] = 2
        return num_founds

    def update_fixed_field(self, issuekey, cols_at_7, no_overwrite_idxs=None):
        new_row = [None, None, None, None, None, None, None]
        new_row.extend(cols_at_7)

        worksheet_name = 'atask'
        worksheet = self.get_sheet(worksheet_name)
        url = self.url + '/browse/' + issuekey
        recs = self.search_records_1(6, url, worksheet)
        ATASK_SADRAFT_IDX = 7
        if len(recs)==0:
            pass
        elif len(recs)==1:
            merged = i_gsheet.merge_rec(recs[0][1], new_row, no_overwrite_idxs)
            update(worksheet, 'A{row}:{col}{row}'.format(row=recs[0][0], col=chr(ord('A')+len(merged))), [merged])
        else:
            pass
