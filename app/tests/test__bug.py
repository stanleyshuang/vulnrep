# -*- coding: utf-8 -*-
#
# Author:   Stanley Huang
# Project:  vulnrep ver. 1.1
# Date:     2023/11/06
#
import os
import unittest
from jira import JIRA
from pkg._qjira.task import analysis_task
from pkg._qjira.bug import vuln_bug
from pkg._util.util_debug import debug

class VulnBugTestCase(unittest.TestCase):
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
    
    def test_run_10(self):
        jira = JIRA(basic_auth=(self.jira_username, self.jira_password), options={'server': self.jira_url})
        root_jira = jira.issue('INTSI000-4509', expand='changelog')
        the_task = analysis_task(jira, root_jira, self.debugobj)
        the_jira = jira.issue('INTSI000-4527', expand='changelog')
        the_bug = vuln_bug(jira, the_jira, self.debugobj)
        bug_raw, children = the_bug.run(the_task, the_bug, self.data, self.downloads, True)
        self.assertTrue('not_affected' == the_bug._b_fix_status and
                        '2023-03-21' == bug_raw['created'] and 
                        0 == len(children))

