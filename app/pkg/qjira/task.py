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
from .function import parse_salesforce_link

class task(i_issue):
    '''
    Jira task
    '''
    def __init__(self, jira, issue):
        super(task, self).__init__(jira, issue)
        if get_issuetype(self.issue) != 'Task':
            raise Exception("Jira issuetype mismatch!!")

class analysis_task(task):
    '''
    Jira task for vulnerabilty analysis
    '''
    def __init__(self, jira, issue):
        super(analysis_task, self).__init__(jira, issue)
        self.sf_data = {}
        self.b_analysis_phase_done = False
        self.analysis_phase_data = []

    def get_sf_case_num(self):
        print('Get SF Case Number')
        description = self.issue.fields.description
        b_need_update, name, link, others = parse_salesforce_link(description)
        if len(name):
            return name.strip()
        return None

    def set_sf_data(self, sf_case_num, created_date, researcher_email, researcher_name):
        print('Update SF Data')
        jira_id = self.issue.id
        summary = self.issue.fields.summary
        print('--- Jira [{jira_id}]{summary}'.format(jira_id=jira_id, summary=summary))

        ### Update Salseforce link, researcher information
        description = self.issue.fields.description
        b_need_update, case_num, link, others = parse_salesforce_link(description)
        researcher_email_index = description.find(researcher_email)
        researcher_name_index = description.find(researcher_name)
        if b_need_update or researcher_email_index<0 or researcher_name_index<0:
            print('--- Correct Salesforce link [{case_num}|{link}]'.format(case_num=case_num, link=link))
            print('---         Case Number: {case_num}, Researcher: {researcher_name} [{researcher_email}]'.format(
                case_num=case_num,
                researcher_name=researcher_name,
                researcher_email=researcher_email))
            self.issue.update(description = '[{case_num}|{link}]\n[{researcher_name}] [{researcher_email}]\n{others}'.format(
                case_num=case_num, 
                link=link,
                researcher_name=researcher_name,
                researcher_email=researcher_email,
                others=others))

        ### Add 'vulnerability_report' in components
        b_vulnerability_report = False
        existingComponents = []
        for component in self.issue.fields.components:
            existingComponents.append({"name" : component.name})
            if component.name=='vulnerability_report':
                b_vulnerability_report = True
        if not b_vulnerability_report:
            existingComponents.append({"name" : 'vulnerability_report'})
            print('--- Add Components: vulnerability_report')
            self.issue.update(fields={"components": existingComponents})

        ### Update date
        created_datetime = datetime.strptime(created_date, '%Y-%m-%dT%H:%M:%S.000+0000')
        deadline = pick_n_days_after(created_datetime, 60)
        created_date_str = utc_to_local_str(created_datetime, format='%Y-%m-%d')
        deadline_str = utc_to_local_str(deadline, format='%Y-%m-%d')
        # Vulnerability Reporting Date: customfield_16400
        # Release Deadline:             customfield_16401
        # Finish ETA:                   customfield_11504
        if self.issue.raw['fields']["customfield_16400"] != created_date_str:
            self.issue.update(fields={"customfield_16400": created_date_str})
            print('--- Update Vulnerability Reporting Date  {created_date_str}'.format(created_date_str=created_date_str))
        if self.issue.raw['fields']["customfield_16401"] != deadline_str:
            self.issue.update(fields={"customfield_16401": deadline_str})
            print('--- Update Release Deadline              {deadline_str}'.format(deadline_str=deadline_str))
        if self.issue.raw['fields']["customfield_11504"] != deadline_str:
            self.issue.update(fields={"customfield_11504": deadline_str})
            print('--- Update Finish ETA                    {deadline_str}'.format(deadline_str=deadline_str))

    def search_result(self):
        '''
        b_analysis_phase_done:  analysis done or not
        analysis_phase_data:    {
                                    'summary': analysis summary,
                                    'author': analyst who gave the comment
                                    'created_date': date time in format '2021-05-13'
                                }
        '''
        print('Find analysis result')
        self.b_analysis_phase_done = False
        self.analysis_phase_data = []
        comments = self.issue.fields.comment.comments
        for comment in comments:
            cid = comment.id
            author = comment.author.displayName
            time = datetime.strptime(comment.created, '%Y-%m-%dT%H:%M:%S.000+0800')
            body = comment.body
            lines = body.split('\n')
            for line in lines:
                security_idx = line.find('[Security]')
                v1_idx = line.find('[V1]')
                v2_idx = line.find('[V2]')
                v3_idx = line.find('[V3]')
                v4_idx = line.find('[V4]')
                v5_idx = line.find('[V5]')
                if security_idx>=0 and (v1_idx>=0 or v2_idx>=0 or v3_idx>=0 or v4_idx>=0 or v5_idx>=0):
                    print('--- Analysis is DONE as {line}'.format(line=line))
                    self.b_analysis_phase_done = True
                    analysis_case = {}
                    analysis_case['summary'] = line
                    analysis_case['author'] = author
                    analysis_case['created_date'] = utc_to_local_str(time, format='%Y-%m-%d')
                    self.analysis_phase_data.append(analysis_case)
        if not self.b_analysis_phase_done:
            print('--- Analysis is on going')
        return self.b_analysis_phase_done, self.analysis_phase_data

    def search_bugfix_result(self):
        from .bug import vuln_bug
        '''
        b_bugfix_phase_done:    bugfix done or not
        bugfix_phase_data:      {
                                    'key': jira key
                                    'summary': jira summary,
                                    'created_date': date time in format '2021-05-13',
                                }
        '''
        b_bugfix_phase_done = True
        bugfix_phase_data = []

        if not self.b_blocked_run:
            self.search_blocked()
        ### enumerate blocked issues and find bugs in the anslysis task 
        for blocked_issue in self.blocked_issues:
            if get_issuetype(blocked_issue) == 'Bug':
                the_bug = vuln_bug(self.jira, blocked_issue)
                b_bugfix_done, bugfix_data = the_bug.search_result()
                if not b_bugfix_done:
                    b_bugfix_phase_done = False
                bugfix_phase_data.extend(bugfix_data)
        return b_bugfix_phase_done, bugfix_phase_data

    def search_arp_result(self):
        from .bug import vuln_bug, app_release_process
        '''
        b_arp_phase_done:   arp done or not
        arp_phase_data:     {
                                'key': jira key
                                'summary': jira summary,
                                'created_date': date time in format '2021-05-13',
                            }
        '''
        b_arp_phase_done = True
        arp_phase_data = []

        if not self.b_blocked_run:
            self.search_blocked()
        ### enumerate blocked issues and find bugs in the anslysis task 
        for blocked_issue in self.blocked_issues:
            if get_issuetype(blocked_issue) == 'Bug':
                the_bug = vuln_bug(self.jira, blocked_issue)

                if not the_bug.b_blocking_run:
                    the_bug.search_blocking()
                ### enumberate blocking issues and find app release process in the bug
                for blocking_issue in the_bug.blocking_issues:
                    if get_issuetype(blocking_issue) == 'App Release Process':
                        the_app_release = app_release_process(self.jira, blocking_issue)
                        b_arp_done, arp_data = the_app_release.search_result()
                        if not b_arp_done:
                            b_arp_phase_done = False
                        arp_phase_data.extend(arp_data)
        return b_arp_phase_done, arp_phase_data
                
    def set_status(self, sf_data={}, 
                   analysis_phase_data=[],
                   bugfix_phase_data=[],
                   arp_phase_data=[]):
        print('Update Status')
        ### Salseforce case_num, link, researcher information
        description = self.issue.fields.description
        b_need_update, case_num, link, others = parse_salesforce_link(description)

        ### Update Salesforce
        if sf_data and bool(sf_data):
            self.sf_data = sf_data
        if 'sf_link' not in self.sf_data:
            self.sf_data['sf_link'] = link
        str_customfield_13600 = json.dumps(self.sf_data) + '\n'

        ### Update Analysis
        if not analysis_phase_data or len(analysis_phase_data)==0:
            analysis_phase_data = self.analysis_phase_data
        str_customfield_13600 += json.dumps(analysis_phase_data) + '\n'

        if bugfix_phase_data and len(bugfix_phase_data)>0:
            str_customfield_13600 += json.dumps(bugfix_phase_data) + '\n'

        if arp_phase_data and len(arp_phase_data)>0:
            str_customfield_13600 += json.dumps(arp_phase_data) + '\n'

        # Status Update: customfield_13600
        if self.issue.raw['fields']["customfield_13600"] != str_customfield_13600:
            self.issue.update(fields={"customfield_13600": str_customfield_13600})

    def resolved(self):
        from .bug import vuln_bug, app_release_process

        if self.b_solved_run:
            return self.unresolved_counts==0, self.unresolved_counts

        self.b_solved_run = True
        self.unresolved_counts = 0
        if not self.b_blocked_run:
            self.search_blocked()

        ### enumerate blocked issues and find bugs in the anslysis task 
        for blocked_issue in self.blocked_issues:
            if get_issuetype(blocked_issue) == 'Bug':
                the_bug = vuln_bug(self.jira, blocked_issue)
                b_resolved, the_bug_unresolved_counts = the_bug.resolved()
                self.unresolved_counts += the_bug_unresolved_counts

        return self.unresolved_counts==0, self.unresolved_counts

