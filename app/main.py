#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  mantisanalyzer 1.0
# Date:     2021-06-03
#
import os
import sys

from jira import JIRA
from util.util_text_file import get_lines

def output_text(filepath, content):
    fp = open(filepath, "a")    # 開啟檔案
    fp.write(content)           # 寫入 This is a testing! 到檔案
    fp.close()                  # 關閉檔案

### get argv[1] as input
if len(sys.argv) >=4:
    username = sys.argv[1]
    password = sys.argv[2]
    jira_id = sys.argv[3]
else:
    print('usage: python main.py [username] [password] [jira id]\n')
    quit()

### the main program
server = 'https://qnap-jira.qnap.com.tw'
jira = JIRA(basic_auth=(username, password), options={'server': server})

issue = jira.issue(jira_id)
summary = issue.fields.summary         # 'Field level security permissions'
# votes = issue.fields.votes.votes       # 440 (at least)
print(summary)

