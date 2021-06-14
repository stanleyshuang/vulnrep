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

from pkg.qjira.task import analysis_task
from pkg.qjira.bug import vuln_bug, app_release_process
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
    print('function: one of --analysis or --bugfix, default value is --analysis')
    quit()

def run_arp(jira, issue):
    the_issue = app_release_process(jira, issue)
    b_solved, unsolved_counts, unsolved_issues = the_issue.resolved()
    print('--------------------------')
    if b_solved:
        print('THE ISSUE IS RESOLVED')
    else:
        print('THE ISSUE IS NOT RESOLVED, unsolved counts is {unsolved_counts}'.format(unsolved_counts=unsolved_counts))
    print('--------------------------')

def run_vuln_bug(jira, issue):
    bug = vuln_bug(jira, issue)
    bug.search_blocking()
    b_solved, unsolved_counts, unsolved_issues = bug.resolved()
    print('--------------------------')
    if b_solved:
        print('THE ISSUE IS RESOLVED')
    else:
        print('THE ISSUE IS NOT RESOLVED, unsolved counts is {unsolved_counts}'.format(unsolved_counts=unsolved_counts))
    print('--------------------------')

def run_analyze_task(jira, issue, b_update=False):
    ana_task = analysis_task(jira, issue)

    b_analysis_phase_done, analysis_phase_data = ana_task.search_result()
    b_solved, unsolved_counts, unsolved_issues = ana_task.resolved()
    print('--------------------------')
    if b_analysis_phase_done and b_solved:
        print('THE ISSUE IS RESOLVED')
    else:
        print('THE ISSUE IS NOT RESOLVED')
        if not b_analysis_phase_done:
            print('    analysis is on going..')
        print('    unsolved counts is {unsolved_counts}'.format(unsolved_counts=unsolved_counts))
    print('--------------------------')

    unsolved_data = {}
    unsolved_data['counts'] = unsolved_counts
    unsolved_data['issues'] = unsolved_issues

    sf_case_num = ana_task.get_sf_case_num()
    if sf_case_num:
        case_num, created_date, email, name, sf_data = sf_get_data(salesforce_orgid, salesforce_username, salesforce_password, sf_case_num)
        if case_num:
            ana_task.set_sf_data(case_num, created_date, email, name)
            if b_update:
                ana_task.set_status(sf_data, 
                                    analysis_phase_data,
                                    unsolved_data)
    
if len(sys.argv) == 1:
    usage()

### get argv[1] as input
jira_id = ''
cmd = 'standard'
func = 'analysis'
for idx in range(1, len(sys.argv)):
    if sys.argv[idx] in ['--standard', '--update', '--verbose', '--test', '--batch']:
        cmd = sys.argv[idx][2:]
    elif sys.argv[idx] in ['standard', 'update', 'verbose', 'test', 'batch']:
        cmd = sys.argv[idx]
    elif sys.argv[idx] in ['--analysis', '--bugfix']:
        func = sys.argv[idx][2:]
    elif sys.argv[idx] in ['analysis', 'bugfix']:
        func = sys.argv[idx]
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

if cmd=='batch':
    jira = JIRA(basic_auth=(jira_username, jira_password), options={'server': jira_url})
    for an_issue in jira.search_issues('project = INTSI000 AND type = Task AND component = vulnerability_report ORDER BY key ASC'):
        run_analyze_task(jira, an_issue, b_update=True)
    quit()
else:
    jira, issue = get_jira_issue(jira_url, jira_username, jira_password, jira_id)
'''
print('Jira Issue Running..')
print('--')
print('function: {func}'.format(func=func))
print('cmd:      {cmd}'.format(cmd=cmd))
print('Jira:     {jira_id}'.format(jira_id=jira_id))
'''
if func=='bugfix':
    if cmd=='standard' or cmd=='verbose' or cmd=='update':
        run_vuln_bug(jira, issue)
else:
    # func == 'analysis'
    if cmd=='standard' or cmd=='verbose' or cmd=='update':
        run_analyze_task(jira, issue, b_update=(cmd=='update'))

if cmd=='test':
    run_arp(jira, issue)

if cmd=='verbose':
    if func=='bugfix':
        the_issue = bug
    else:
        the_issue = ana_task
    the_issue.dump()

