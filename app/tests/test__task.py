# -*- coding: utf-8 -*-
#
# Author:   Stanley Huang
# Project:  vulnrep ver. 1.0
# Date:     2023/10/28
#
import os
import unittest
from jira import JIRA
from pkg._qjira.task import analysis_task
from pkg._qjira.bug import vuln_bug
from pkg._util.util_debug import debug

class AnalysisTaskTestCase(unittest.TestCase):
    def setUp(self):
        self.jira_url = os.environ.get('jira_url')
        self.jira_username = os.environ.get('jira_username')
        self.jira_password = os.environ.get('jira_password')
        self.debugobj = debug('regular')
        apphome = os.environ.get('apphome')
        self.data = apphome + '/data'
        self.downloads = apphome + '/downloads'

    def tearDown(self):
        pass
    
    def test_task_10(self):
        jira = JIRA(basic_auth=(self.jira_username, self.jira_password), options={'server': self.jira_url})
        root_jira = jira.issue('INTSI000-4509', expand='changelog')
        the_task = analysis_task(jira, root_jira, self.debugobj)
        self.assertTrue(True)

