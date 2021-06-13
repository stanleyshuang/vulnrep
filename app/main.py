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

from pkg.qjira.issue import analysis_task, vuln_bug
from pkg.qsalesforce import sf_get_data
from pkg.util.util_text_file import get_lines, flush_text


def get_jira_issue(server, username, password, jira_id):
    jira = JIRA(basic_auth=(username, password), options={'server': server})
    return jira, jira.issue(jira_id)

def usage():
    print('USAGE:    python main.py jira_id [cmd] [function]')
    print('--')
    print('jira_id:  JIRA ticket, for example, INTSI000-732')
    print('cmd:      one of --standard, --update, --verbose or --test, default value is --standard')
    print('function: one of --analysis or --bug_fix, default value is --analysis')
    quit()
    

if len(sys.argv) == 1:
    usage()

### get argv[1] as input
jira_id = ''
cmd = 'standard'
func = 'analysis'
for idx in range(1, len(sys.argv)):
    if sys.argv[idx] in ['--standard', '--update', '--verbose', '--test']:
        cmd = sys.argv[idx][2:]
    if sys.argv[idx] in ['standard', 'update', 'verbose', 'test']:
        cmd = sys.argv[idx]
    elif sys.argv[idx] in ['--analysis', '--bug_fix']:
        func = sys.argv[idx][2:]
    elif sys.argv[idx] in ['analysis', 'bug_fix']:
        func = sys.argv[idx]
    else:
        jira_id = sys.argv[idx]

if jira_id == '':
    usage()

### the main program
# Get environment variables
jira_url = os.environ.get('jira_url')
jira_username = os.environ.get('jira_username')
jira_password = os.environ.get('jira_password')

salesforce_url = os.environ.get('salesforce_url')
salesforce_username = os.environ.get('salesforce_username')
salesforce_password = os.environ.get('salesforce_password')
salesforce_orgid = os.environ.get('salesforce_orgid')

jira, issue = get_jira_issue(jira_url, jira_username, jira_password, jira_id)

print('Jira Issue Running..')
print('--')
print('function: {func}'.format(func=func))
print('cmd:      {cmd}'.format(cmd=cmd))
print('Jira:     {jira_id}'.format(jira_id=jira_id))

if func=='bug_fix':
    if cmd=='standard' or cmd=='verbose' or cmd=='update':
        bug = vuln_bug(jira, issue)
        bug.search_blocking()
else:
    # func == 'analysis'
    if cmd=='standard' or cmd=='verbose' or cmd=='update':
        ana_task = analysis_task(jira, issue)

        b_analyzed, analysis_cases = ana_task.search_result()
        b_bug_created, blocked_issues = ana_task.search_blocked()

        sf_case_num = ana_task.get_sf_case_num()
        if sf_case_num:
            case_num, created_date, email, name, sf_dict = sf_get_data(salesforce_orgid, salesforce_username, salesforce_password, sf_case_num)
            if case_num:
                ana_task.set_sf_data(case_num, created_date, email, name)
                if cmd=='update':
                    ana_task.set_status(sf_dict, analysis_cases)

if cmd=='test':
        pass

if cmd=='verbose':
    if func=='bug_fix':
        the_issue = bug
    else:
        the_issue = ana_task
    the_issue.dump()

