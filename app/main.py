#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2021-06-04
#
import json
import os, sys
from jira import JIRA

from pkg.qjira import get_issuetype
from pkg.qjira.task import analysis_task
from pkg.qjira.bug import vuln_bug, app_release_process, fw_release_process
from pkg.qsalesforce import sf_get_data
from pkg.util.util_file import create_folder


def get_jira_issue(server, username, password, jira_id):
    jira = JIRA(basic_auth=(username, password), options={'server': server})
    return jira, jira.issue(jira_id, expand='changelog')

def usage():
    print('USAGE:    python main.py cmd [mode] jira_id')
    print('--')
    print('cmd:      one of --standard or --update, default value is --standard')
    print('mode:     one of --verbose or --regular')
    print('jira_id:  JIRA ticket, for example, INTSI000-732')
    print('-------------------------------------------------')
    print('USAGE:    python main.py cmd')
    print('--')
    print('cmd:      one of --batch or --test')
    print('          batch for batch running')
    print('          test for unit test')
    quit()
    
if len(sys.argv) == 1:
    usage()

### get argv[1] as input
jira_id = ''
cmd = 'standard'
mode = 'regular'
for idx in range(1, len(sys.argv)):
    if sys.argv[idx] in ['--standard', '--update', '--test', '--batch']:
        cmd = sys.argv[idx][2:]
    elif sys.argv[idx] in ['standard', 'update', 'test', 'batch']:
        cmd = sys.argv[idx]
    elif sys.argv[idx] in ['--verbose']:
        mode = sys.argv[idx][2:]
    elif sys.argv[idx] in ['verbose']:
        mode = sys.argv[idx]
    else:
        jira_id = sys.argv[idx]

### the main program
# Get environment variables
jira_url = os.environ.get('jira_url')
jira_username = os.environ.get('jira_username')
jira_password = os.environ.get('jira_password')

salesforce_url = os.environ.get('salesforce_url')
salesforce_username = os.environ.get('salesforce_username')
salesforce_password = os.environ.get('salesforce_password')
salesforce_orgid = os.environ.get('salesforce_orgid')

### Create downloads folder
apphome = os.environ.get('apphome')
downloads = apphome + '/downloads'
create_folder(downloads)

if cmd=='batch':
    jira = JIRA(basic_auth=(jira_username, jira_password), options={'server': jira_url})
    for an_issue in jira.search_issues('project = INTSI000 AND type = Task AND component = vulnerability_report ORDER BY key ASC'):
        run_analyze_task(jira, an_issue, downloads, b_update=True)
elif cmd=='test':
    import unittest
    tests = unittest.TestLoader().discover('tests')
    unittest.TextTestRunner(verbosity=2).run(tests)
else: # cmd in ['standard', 'update']
    jira, issue = get_jira_issue(jira_url, jira_username, jira_password, jira_id)
    if get_issuetype(issue)=='Task':
        the_issue = analysis_task(jira, issue)
        ### get and set SF data
        sf_case_num = the_issue.get_sf_case_num()
        if sf_case_num:
            case_num, created_date, email, name, sf_data = sf_get_data(salesforce_orgid, salesforce_username, salesforce_password, sf_case_num)
            if case_num:
                the_issue.set_sf_data(case_num, created_date, email, name)
    elif get_issuetype(issue)=='Bug':
        the_issue = vuln_bug(jira, issue)
    elif get_issuetype(issue)=='App Release Process':
        the_issue = app_release_process(jira, issue)
    elif get_issuetype(issue)=='FW Release Process':
        the_issue = fw_release_process(jira, issue)
    else:
        quit()

    issue_status = the_issue.run(downloads, b_update=(cmd=='update'))

    ### update Status Update
    if get_issuetype(issue)=='Task' and (cmd=='update') and sf_case_num and case_num:
        the_issue.set_status(sf_data, issue_status)

if the_issue and mode=='verbose':
    the_issue.dump()

