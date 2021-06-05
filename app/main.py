#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2021-06-04
#
import os
import sys

from pkg.qjira import j_get_sf_case_num, j_update_sf_data
from pkg.qsalesforce import sf_get_data
from pkg.util.util_text_file import get_lines, flush_text
    

### get argv[1] as input
if len(sys.argv) >= 2:
    jira_id = sys.argv[1]
else:
    print('usage: python main.py [jira id]\n')
    quit()

### the main program
# Get environment variables
jira_url = os.environ.get('jira_url')
jira_username = os.environ.get('jira_username')
jira_password = os.environ.get('jira_password')

salesforce_url = os.environ.get('salesforce_url')
salesforce_username = os.environ.get('salesforce_username')
salesforce_password = os.environ.get('salesforce_password')
salesforce_orgid = os.environ.get('salesforce_orgid')

sf_case_num = j_get_sf_case_num(jira_url, jira_username, jira_password, jira_id)
if sf_case_num:
    case_num, created_date, email, name = sf_get_data(salesforce_orgid, salesforce_username, salesforce_password, sf_case_num)
    if case_num:
        j_update_sf_data(jira_url, jira_username, jira_password, jira_id, case_num, created_date, email, name)
