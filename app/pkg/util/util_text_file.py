#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  util 1.0
# Date:     2021-06-04
# 

def get_lines(filename):
    with open(filename, 'r') as fp:
         all_lines = fp.readlines()
         return all_lines
    return None

def flush_text(filename, content):
    fp = open(filename, "a")    # 開啟檔案
    fp.write(content)           # 寫入 This is a testing! 到檔案
    fp.close()                  # 關閉檔案