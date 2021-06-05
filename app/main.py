#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2021-06-04
#
import os
import sys

from jira import JIRA
from util.util_text_file import get_lines, flush_text

def extract_str_in_link(content):
    import re
    # regex to extract required strings
    reg_str = r"\[(.*?)\]"
    in_bracket = re.search(reg_str, content)
    if in_bracket:
        res = in_bracket.group(1).split('|')
        if not res or len(res)<=2:
            return '', '', content
        return res[0], res[len(res)-1], content[in_bracket.end():]
    return '', '', content

def parse_salesforce_link(content):
    name, link, others = extract_str_in_link(content)
    return name, link, others
    

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
votes = issue.fields.votes.votes       # 440 (at least)
description = issue.fields.description
print(summary)
print(votes)
name, link, others = parse_salesforce_link(description)
if len(name) > 0 and len(link) > 0:
    print('--- Correct Salesforce link [{name}|{link}]'.format(name=name, link=link))
    issue.update(description = '[{name}|{link}]{others}'.format(name=name, link=link, others=others))
