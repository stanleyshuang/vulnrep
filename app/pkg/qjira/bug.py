#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2021-06-13
#
import json
from datetime import datetime
from pkg.util.util_datetime import pick_n_days_after, utc_to_local_str
from . import i_issue, get_issuetype

class bug(i_issue):
    '''
    Jira bug
    '''
    def __init__(self, jira, issue):
        super(bug, self).__init__(jira, issue)
        if get_issuetype(self.issue) != 'Bug':
            raise Exception("Jira issuetype mismatch!!")

class vuln_bug(bug):
    '''
    Jira bug for vulnerabilty fixing
    '''
    def __init__(self, jira, issue):
        super(vuln_bug, self).__init__(jira, issue)
        self.apprelease_counts = 0
        self.fwrelease_counts = 0
        
    def collect_unresolved_issues(self):
        if self.b_unresolved_run:
            return

        self.b_unresolved_run = True
        self.unresolved_counts = 0
        self.unresolved_issues = []
        self.apprelease_counts = 0
        self.fwrelease_counts = 0

        self.search_blocking()
        ### enumberate blocking issues and find app release process in the bug
        for blocking_issue in self.blocking_issues:
            if get_issuetype(blocking_issue) == 'App Release Process':
                the_app_release = app_release_process(self.jira, blocking_issue)
                the_app_release.collect_unresolved_issues()
                self.unresolved_counts += the_app.release_unresolved_counts
                self.unresolved_issues.extend(the_app.release_unresolved_issues)
                self.apprelease_counts += 1
            elif get_issuetype(blocking_issue) == 'FW Release Process':
                the_fw_release = fw_release_process(self.jira, blocking_issue)
                the_fw_release.collect_unresolved_issues()
                self.unresolved_counts += the_fw_release.unresolved_counts
                self.unresolved_issues.extend(the_fw_release.unresolved_issues)
                self.fwrelease_counts += 1

        time = datetime.strptime(self.issue.fields.created, '%Y-%m-%dT%H:%M:%S.000+0800')
        str_time = utc_to_local_str(time, format='%Y-%m-%d')
        if self.get_status_name() not in ['verified', 'abort']:
            self.unresolved_counts += 1
            self.unresolved_issues.append({
                    'key': self.issue.key,
                    'created': str_time,
                    'issuetype': get_issuetype(self.issue),
                    'status': self.get_status_name(),
                    'summary': self.issue.fields.summary,
                })

    def resolved(self):
        status = self.get_status_name()
        return (status=='verified' and self.unresolved_counts==0 and self.apprelease_counts+self.fwrelease_counts>0) or status=='abort'

    def run(self, downloads, b_update=False):
        issue_status = {}
        self.collect_unresolved_issues()

        if self.resolved():
            author, created, status = self.get_auther_and_created_in_changlog('status', ['verified', 'abort'])
            created = datetime.strptime(created, '%Y-%m-%dT%H:%M:%S.000+0800')
            str_created = utc_to_local_str(created, format='%Y-%m-%d')
            issue_status['summary'] = 'RESOLVED, {author}, {str_created}'.format(author=author, str_created=str_created)
            issue_status['author'] = author
            issue_status['latest_updated'] = str_created
            issue_status['issue_status'] = status
        else:
            issue_status['summary'] = 'NOT RESOLVED'
            issue_status['unsolved_cases'] = {}
            issue_status['unsolved_cases']['counts'] = self.unresolved_counts
            if len(self.unresolved_issues)>0:
                issue_status['unsolved_cases']['cases'] = self.unresolved_issues
        print(json.dumps(issue_status, indent=4))

class fw_release_process(i_issue):
    '''
    Jira fw_release_process
    '''
    def __init__(self, jira, issue):
        super(fw_release_process, self).__init__(jira, issue)
        if get_issuetype(self.issue) != 'FW Release Process':
            raise Exception("Jira issuetype mismatch!!")
        
    def collect_unresolved_issues(self):
        if self.b_unresolved_run:
            return

        self.b_unresolved_run = True
        self.unresolved_counts = 0
        self.unresolved_issues = []

        if self.get_status_name() not in ['done', 'abort']:
            time = datetime.strptime(self.issue.fields.created, '%Y-%m-%dT%H:%M:%S.000+0800')
            str_time = utc_to_local_str(time, format='%Y-%m-%d')
            str_eta = self.issue.raw['fields']["customfield_11504"]
            self.unresolved_counts += 1
            self.unresolved_issues.append({
                    'key': self.issue.key,
                    'created': str_time,
                    'issuetype': get_issuetype(self.issue),
                    'status': self.get_status_name(),
                    'summary': self.issue.fields.summary,
                    'eta': str_eta
                })

    def resolved(self):
        return self.get_status_name() in ['done', 'abort']

    def run(self, downloads, b_update=False):
        issue_status = {}
        self.collect_unresolved_issues()

        if self.resolved():
            author, created, status = self.get_auther_and_created_in_changlog('status', ['done', 'abort'])
            created = datetime.strptime(created, '%Y-%m-%dT%H:%M:%S.000+0800')
            str_created = utc_to_local_str(created, format='%Y-%m-%d')
            issue_status['summary'] = 'RESOLVED, {author}, {str_created}'.format(author=author, str_created=str_created)
            issue_status['author'] = author
            issue_status['latest_updated'] = str_created
            issue_status['issue_status'] = status
        else:
            issue_status['summary'] = 'NOT RESOLVED'
            issue_status['unsolved_cases'] = {}
            issue_status['unsolved_cases']['counts'] = self.unresolved_counts
            if len(self.unresolved_issues)>0:
                issue_status['unsolved_cases']['cases'] = self.unresolved_issues
        print(json.dumps(issue_status, indent=4))

class app_release_process(i_issue):
    '''
    Jira app_release_process
    '''
    def __init__(self, jira, issue):
        super(app_release_process, self).__init__(jira, issue)
        if get_issuetype(self.issue) != 'App Release Process':
            raise Exception("Jira issuetype mismatch!!")

    def collect_unresolved_issues(self):
        if self.b_unresolved_run:
            return

        self.b_unresolved_run = True
        self.unresolved_counts = 0
        self.unresolved_issues = []

        if self.get_status_name() not in ['done', 'abort']:
            time = datetime.strptime(self.issue.fields.created, '%Y-%m-%dT%H:%M:%S.000+0800')
            str_time = utc_to_local_str(time, format='%Y-%m-%d')
            eta = self.issue.raw['fields']["customfield_11504"]
            str_eta = utc_to_local_str(eta, format='%Y-%m-%d')
            self.unresolved_counts += 1
            self.unresolved_issues.append({
                    'key': self.issue.key,
                    'created': str_time,
                    'issuetype': get_issuetype(self.issue),
                    'status': self.get_status_name(),
                    'summary': self.issue.fields.summary,
                    'eta': str_eta
                })

    def resolved(self):
        return self.get_status_name() in ['done', 'abort']

    def run(self, downloads, b_update=False):
        issue_status = {}
        self.collect_unresolved_issues()

        if self.resolved():
            author, created, status = self.get_auther_and_created_in_changlog('status', ['done', 'abort'])
            created = datetime.strptime(created, '%Y-%m-%dT%H:%M:%S.000+0800')
            str_created = utc_to_local_str(created, format='%Y-%m-%d')
            issue_status['summary'] = 'RESOLVED, {author}, {str_created}'.format(author=author, str_created=str_created)
            issue_status['author'] = author
            issue_status['latest_updated'] = str_created
            issue_status['issue_status'] = status
        else:
            issue_status['summary'] = 'NOT RESOLVED'
            issue_status['unsolved_cases'] = {}
            issue_status['unsolved_cases']['counts'] = self.unresolved_counts
            if len(self.unresolved_issues)>0:
                issue_status['unsolved_cases']['cases'] = self.unresolved_issues
        print(json.dumps(issue_status, indent=4))
        