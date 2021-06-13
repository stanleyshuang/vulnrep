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
        unresolved_counts = 0
        if not self.b_blocking_run:
            self.search_blocking()

        ### enumberate blocking issues and find app release process in the bug
        for blocking_issue in self.blocking_issues:
            if get_issuetype(blocking_issue) == 'App Release Process':
                the_app_release = app_release_process(self.jira, blocking_issue)
                b_resolved, the_app_release_unresolved_counts = the_app_release.resolved()
                unresolved_counts += the_app_release_unresolved_counts

        if unresolved_counts>0:
            return False, unresolved_counts
        return True, 0


class app_release_process(i_issue):
    '''
    Jira app_release_process
    '''
    def __init__(self, jira, issue):
        super(app_release_process, self).__init__(jira, issue)
        if get_issuetype(self.issue) != 'App Release Process':
            raise Exception("Jira issuetype mismatch!!")
        
    def resolved(self):
        if self.get_status().lower() in ['done', 'abort']:
            return True, 0
        else:
            return False, 1

