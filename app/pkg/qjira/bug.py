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
from . import i_issue

class bug(i_issue):
    '''
    Jira bug
    '''
    def __init__(self, jira, issue):
        super(bug, self).__init__(jira, issue)
        if self.get_issuetype() != 'Bug':
            raise Exception("Jira issuetype mismatch!!")

class vuln_bug(bug):
    '''
    Jira bug for vulnerabilty fixing
    '''
    def __init__(self, jira, issue):
        super(vuln_bug, self).__init__(jira, issue)

