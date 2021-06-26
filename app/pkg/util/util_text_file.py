#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  util 1.0
# Date:     2021-06-04
# 
import json

def get_lines(filename):
    with open(filename, 'r') as fp:
         all_lines = fp.readlines()
         return all_lines
    return None

def flush_text(filename, content):
    fp = open(filename, "a")    # 開啟檔案
    fp.write(content)           # 寫入 This is a testing! 到檔案
    fp.close()                  # 關閉檔案

def output_text(filepath, content):
    fp = open(filepath, "w")    # 開啟檔案
    fp.write(content)           # 寫入 This is a testing! 到檔案
    fp.close()                  # 關閉檔案
   
def open_json(filename):
    with open(filename) as data_file:
        data = json.load(data_file)
    return data
    
def dump_json(filename, data):
    json_str = json.dumps(data, sort_keys=True, indent=4, ensure_ascii=False)
    fp = open(filename, "w")    # 開啟檔案
    fp.write(json_str)          # 寫入 This is a testing! 到檔案
    fp.close()                  # 關閉檔案