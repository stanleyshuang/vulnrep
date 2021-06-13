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
        self.b_bugfix_phase_done = False
        self.bugfix_phase_data = []

    def search_result(self):
        '''
        b_bugfix_phase_done:    bugfix done or not
        bugfix_phase_data:      {
                                    'key': jira key
                                    'summary': jira summary,
                                    'created_date': date time in format '2021-05-13',
                                }
        '''
        print('Find bugfix result')
        self.resolved()
        print('>>> bugfix_phase_data - ' + json.dumps(self.bugfix_phase_data))
        return self.b_bugfix_phase_done, self.bugfix_phase_data
        
    def resolved(self):
        if self.b_solved_run:
            return self.unresolved_counts==0, self.unresolved_counts

        self.b_solved_run = True
        self.unresolved_counts = 0

        if not self.b_blocking_run:
            self.search_blocking()

        time = datetime.strptime(self.issue.fields.created, '%Y-%m-%dT%H:%M:%S.000+0800')
        str_time = utc_to_local_str(time, format='%Y-%m-%d')

        if self.get_status().lower() in ['verified', 'abort']:
            self.b_bugfix_phase_done = True
        else:
            self.unresolved_counts += 1
            self.bugfix_phase_data.append({
                    'key': self.issue.key,
                    'summary': self.issue.fields.summary,
                    'created_date': str_time,
                })

        ### enumberate blocking issues and find app release process in the bug
        for blocking_issue in self.blocking_issues:
            if get_issuetype(blocking_issue) == 'App Release Process':
                the_app_release = app_release_process(self.jira, blocking_issue)
                b_resolved, the_app_release_unresolved_counts = the_app_release.resolved()
                self.unresolved_counts += the_app_release_unresolved_counts

        return self.unresolved_counts==0, self.unresolved_counts

class app_release_process(i_issue):
    '''
    Jira app_release_process
    '''
    def __init__(self, jira, issue):
        super(app_release_process, self).__init__(jira, issue)
        if get_issuetype(self.issue) != 'App Release Process':
            raise Exception("Jira issuetype mismatch!!")
        self.b_arp_phase_done = False
        self.arp_phase_data = []

    def search_result(self):
        '''
        b_arp_phase_done:   app release process done or not
        arp_phase_data:     {
                                'key': jira key
                                'summary': jira summary,
                                'created_date': date time in format '2021-05-13',
                            }
        '''
        print('Find arp result')
        self.resolved()
        print('>>> arp_phase_data - ' + json.dumps(self.arp_phase_data))
        return self.b_arp_phase_done, self.arp_phase_data
        
    def resolved(self):
        if self.b_solved_run:
            return self.unresolved_counts==0, self.unresolved_counts

        self.b_solved_run = True
        if self.get_status().lower() in ['done', 'abort']:
            self.unresolved_counts = 0
        else:
            time = datetime.strptime(self.issue.fields.created, '%Y-%m-%dT%H:%M:%S.000+0800')
            str_time = utc_to_local_str(time, format='%Y-%m-%d')
            self.arp_phase_data.append({
                    'key': self.issue.key,
                    'summary': self.issue.fields.summary,
                    'created_date': str_time,
                })
            self.unresolved_counts = 1
        return self.unresolved_counts==0, self.unresolved_counts

