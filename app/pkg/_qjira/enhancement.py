#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.5
# Date:     2024-08-06
#
import json
from datetime import datetime
from pkg._util.util_datetime import duration_days
from .description import extract_model
from . import i_issue, get_issuetype


class i_enhancement(i_issue):
    """
    Jira enhancement
    """

    def __init__(self, jira, issue, debug_mode):
        super(i_enhancement, self).__init__(jira, issue, debug_mode)
        if get_issuetype(self.issue) != "Enhancement":
            raise Exception("Jira issuetype mismatch!!")


class vuln_enhancement(i_enhancement):
    """
    Jira enhancement for vulnerabilty fixing
    """

    def __init__(self, jira, issue, debug_obj):
        super(vuln_enhancement, self).__init__(jira, issue, debug_obj)

    