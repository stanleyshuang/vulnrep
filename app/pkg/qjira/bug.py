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
        
    def resolved(self):
        if self.b_solved_run:
            return self.b_solved, self.unresolved_counts, self.unresolved_issues

        self.b_solved_run = True
        self.unresolved_counts = 0
        self.unresolved_issues = []

        time = datetime.strptime(self.issue.fields.created, '%Y-%m-%dT%H:%M:%S.000+0800')
        str_time = utc_to_local_str(time, format='%Y-%m-%d')
        if self.get_status().lower() not in ['verified', 'abort']:
            self.unresolved_counts += 1
            self.unresolved_issues.append({
                    'key': self.issue.key,
                    'created': str_time,
                    'issuetype': get_issuetype(self.issue),
                    'status': self.get_status().lower(),
                    'summary': self.issue.fields.summary,
                })
            self.status = self.get_status().lower()
        else:
            self.author, created, self.status = self.get_change_auther_and_created('status', ['verified', 'abort'])
            created = datetime.strptime(created, '%Y-%m-%dT%H:%M:%S.000+0800')
            self.str_created = utc_to_local_str(created, format='%Y-%m-%d')

        self.search_blocking()

        ### enumberate blocking issues and find app release process in the bug
        arp_counts = 0
        frp_counts = 0
        for blocking_issue in self.blocking_issues:
            if get_issuetype(blocking_issue) == 'App Release Process':
                the_app_release = app_release_process(self.jira, blocking_issue)
                b_resolved, the_app_release_unresolved_counts, the_app_release_unresolved_issues = the_app_release.resolved()
                self.unresolved_counts += the_app_release_unresolved_counts
                self.unresolved_issues.extend(the_app_release_unresolved_issues)
                arp_counts += 1
            elif get_issuetype(blocking_issue) == 'FW Release Process':
                the_fw_release = fw_release_process(self.jira, blocking_issue)
                b_resolved, the_fw_release_unresolved_counts, the_fw_release_unresolved_issues = the_fw_release.resolved()
                self.unresolved_counts += the_fw_release_unresolved_counts
                self.unresolved_issues.extend(the_fw_release_unresolved_issues)
                frp_counts += 1

        self.b_solved = self.status=='verified' and self.unresolved_counts==0 and arp_counts+frp_counts>0
        return self.b_solved, self.unresolved_counts, self.unresolved_issues

    def run(self, downloads, b_update=False):
        issue_status = {}
        b_solved, unresolved_counts, unresolved_issues = self.resolved()
        if b_solved:
            issue_status['summary'] = 'RESOLVED, {author}, {str_created}'.format(author=self.author, str_created=self.str_created)
        else:
            issue_status['summary'] = 'NOT RESOLVED'
            issue_status['unsolved_cases'] = {}
            issue_status['unsolved_cases']['counts'] = unresolved_counts
            if len(unresolved_issues)>0:
                issue_status['unsolved_cases']['cases'] = unresolved_issues
        print(json.dumps(issue_status, indent=4))
        return issue_status

class fw_release_process(i_issue):
    '''
    Jira fw_release_process
    '''
    def __init__(self, jira, issue):
        super(fw_release_process, self).__init__(jira, issue)
        if get_issuetype(self.issue) != 'FW Release Process':
            raise Exception("Jira issuetype mismatch!!")
        
    def resolved(self):
        if self.b_solved_run:
            return self.b_solved, self.unresolved_counts, self.unresolved_issues

        self.b_solved_run = True
        self.unresolved_counts = 0
        self.unresolved_issues = []

        if self.get_status().lower() not in ['done', 'abort']:
            time = datetime.strptime(self.issue.fields.created, '%Y-%m-%dT%H:%M:%S.000+0800')
            str_time = utc_to_local_str(time, format='%Y-%m-%d')
            str_eta = self.issue.raw['fields']["customfield_11504"]
            self.unresolved_issues.append({
                    'key': self.issue.key,
                    'created': str_time,
                    'issuetype': get_issuetype(self.issue),
                    'status': self.get_status().lower(),
                    'summary': self.issue.fields.summary,
                    'eta': str_eta
                })
            self.unresolved_counts = 1
            self.status = self.get_status().lower()
        else:
            self.author, created, self.status = self.get_change_auther_and_created('status', ['done', 'abort'])
            created = datetime.strptime(created, '%Y-%m-%dT%H:%M:%S.000+0800')
            self.str_created = utc_to_local_str(created, format='%Y-%m-%d')
            self.b_solved = True

        return self.b_solved, self.unresolved_counts, self.unresolved_issues

    def run(self, downloads, b_update=False):
        issue_status = {}
        b_solved, unresolved_counts, unresolved_issues = self.resolved()
        if b_solved:
            issue_status['summary'] = 'RESOLVED, {author}, {str_created}'.format(author=self.author, str_created=self.str_created)
        else:
            issue_status['summary'] = 'NOT RESOLVED'
            issue_status['unsolved_cases'] = {}
            issue_status['unsolved_cases']['counts'] = unresolved_counts
            if len(unresolved_issues)>0:
                issue_status['unsolved_cases']['cases'] = unresolved_issues
        print(json.dumps(issue_status, indent=4))
        return issue_status


class app_release_process(i_issue):
    '''
    Jira app_release_process
    '''
    def __init__(self, jira, issue):
        super(app_release_process, self).__init__(jira, issue)
        if get_issuetype(self.issue) != 'App Release Process':
            raise Exception("Jira issuetype mismatch!!")
        
    def resolved(self):
        if self.b_solved_run:
            return self.b_solved, self.unresolved_counts, self.unresolved_issues

        self.b_solved_run = True
        self.unresolved_counts = 0
        self.unresolved_issues = []

        if self.get_status().lower() not in ['done', 'abort']:
            time = datetime.strptime(self.issue.fields.created, '%Y-%m-%dT%H:%M:%S.000+0800')
            str_time = utc_to_local_str(time, format='%Y-%m-%d')
            eta = self.issue.raw['fields']["customfield_11504"]
            str_eta = utc_to_local_str(eta, format='%Y-%m-%d')
            self.unresolved_issues.append({
                    'key': self.issue.key,
                    'created': str_time,
                    'issuetype': get_issuetype(self.issue),
                    'status': self.get_status().lower(),
                    'summary': self.issue.fields.summary,
                    'eta': str_eta
                })
            self.unresolved_counts = 1
            self.status = self.get_status().lower()
        else:
            self.author, created, self.status = self.get_change_auther_and_created('status', ['done', 'abort'])
            created = datetime.strptime(created, '%Y-%m-%dT%H:%M:%S.000+0800')
            self.str_created = utc_to_local_str(created, format='%Y-%m-%d')
            self.b_solved = True
        return self.b_solved, self.unresolved_counts, self.unresolved_issues

    def run(self, downloads, b_update=False):
        issue_status = {}
        b_solved, unresolved_counts, unresolved_issues = self.resolved()
        if b_solved:
            issue_status['summary'] = 'RESOLVED, {author}, {str_created}'.format(author=self.author, str_created=self.str_created)
        else:
            issue_status['summary'] = 'NOT RESOLVED'
            issue_status['unsolved_cases'] = {}
            issue_status['unsolved_cases']['counts'] = unresolved_counts
            if len(unresolved_issues)>0:
                issue_status['unsolved_cases']['cases'] = unresolved_issues
        print(json.dumps(issue_status, indent=4))
        return issue_status

