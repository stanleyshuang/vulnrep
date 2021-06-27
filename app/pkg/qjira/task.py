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
        self.b_analysis_done = False
        self.b_verification_done = False
        self.b_apprelease_done = False
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
        b_analysis_done:  analysis done or not
        analysis_phase_data:    {
                                    'summary': analysis summary,
                                    'author': analyst who gave the comment
                                    'created': date time in format '2021-05-13'
                                }
        '''
        # print('Find analysis result')
        self.b_analysis_done = False
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
                    # print('--- Analysis is DONE as {line}'.format(line=line))
                    self.b_analysis_done = True
                    analysis_case = {}
                    analysis_case['summary'] = line
                    analysis_case['author'] = author
                    analysis_case['created'] = utc_to_local_str(time, format='%Y-%m-%d')
                    self.analysis_phase_data.append(analysis_case)
        if not self.b_analysis_done and self.get_status()=='abort':
            self.b_analysis_done = True
        if not self.b_analysis_done:
            # print('--- Analysis is on going')
            pass
        return self.b_analysis_done, self.analysis_phase_data

    def run(self, downloads, b_update=False):
        issue_status = {}
        b_solved, unresolved_counts, unresolved_issues = self.resolved()

        self.download_cve_jsons(downloads)
        if b_solved:
            issue_status['summary'] = 'RESOLVED, {author}, {str_created}'.format(author=self.author, str_created=self.str_created)
        else:
            issue_status['summary'] = 'NOT RESOLVED'
            issue_status['analysis'] = {}
            if self.b_analysis_done:
                issue_status['analysis']['status'] = 'done'
                issue_status['analysis']['cases'] = []
                for vuln_case in self.analysis_phase_data:
                    issue_status['analysis']['cases'] = '{summary} {author}, {created}'.format(summary=vuln_case['summary'],
                                                                                               author=vuln_case['author'],
                                                                                               created=vuln_case['created'])
            else:
                issue_status['analysis']['status'] = 'on-going..'

            issue_status['verification'] = {}
            if self.b_verification_done:
                issue_status['verification']['status'] = 'done'

            issue_status['apprelease'] = {}
            if self.b_apprelease_done:
                issue_status['apprelease']['status'] = 'all_uploaded'

            issue_status['unsolved_cases'] = {}
            issue_status['unsolved_cases']['counts'] = unresolved_counts
            if len(unresolved_issues)>0:
                issue_status['unsolved_cases']['cases'] = unresolved_issues

        if self.b_solved:
            issue_status['author'] = self.author
            issue_status['latest_updated'] = self.str_created
            issue_status['issue_status'] = self.status

        print(json.dumps(issue_status, indent=4))
        return issue_status
                
    def set_status(self, sf_data={}, 
                   unsolved_data={}):
        print('Update Status')
        ### Salseforce case_num, link, researcher information
        description = self.issue.fields.description
        b_need_update, case_num, link, others = parse_salesforce_link(description)

        dict_customfield_13600 = {}
        ### Update Salesforce
        if sf_data and bool(sf_data):
            self.sf_data = sf_data
        if 'sf_link' not in self.sf_data:
            self.sf_data['sf_link'] = link
        dict_customfield_13600['SF'] = self.sf_data

        ### Update Analysis
        dict_customfield_13600['ANALYSIS'] = self.analysis_phase_data

        if unsolved_data and bool(unsolved_data):
            dict_customfield_13600['STATUS'] = unsolved_data

        # Status Update: customfield_13600
        str_customfield_13600 = json.dumps(dict_customfield_13600, indent=4)
        if self.issue.raw['fields']["customfield_13600"] != str_customfield_13600:
            print('--- update Status Update (customfield_13600)')
            self.issue.update(fields={"customfield_13600": str_customfield_13600})

    def resolved(self):
        '''
        the following variables would be updated
        self.b_analysis_done
        self.analysis_phase_data
        '''
        self.search_result()

        from .bug import vuln_bug, app_release_process

        if self.b_solved_run:
            return self.b_solved, self.unresolved_counts, self.unresolved_issues

        self.b_solved_run = True
        self.unresolved_counts = 0
        self.unresolved_issues = []

        if not self.b_blocked_run:
            self.search_blocked()
        ### enumerate blocked issues and find bugs in the anslysis task
        self.b_verification_done = True
        for blocked_issue in self.blocked_issues:
            if get_issuetype(blocked_issue) == 'Bug':
                the_bug = vuln_bug(self.jira, blocked_issue)
                b_resolved, the_bug_unresolved_counts, the_bug_unresolved_issues = the_bug.resolved()
                if the_bug.status!='verified':
                    self.b_verification_done = False
                self.unresolved_counts += the_bug_unresolved_counts
                self.unresolved_issues.extend(the_bug_unresolved_issues)
        if self.unresolved_counts == 0:
            self.b_apprelease_done = True

        status = self.issue.fields.status.name.lower()
        self.author, created, self.status = self.get_change_auther_and_created('status', [status])
        created = datetime.strptime(created, '%Y-%m-%dT%H:%M:%S.000+0800')
        self.str_created = utc_to_local_str(created, format='%Y-%m-%d')

        if self.status not in ['close', 'abort']:
            self.unresolved_counts += 1
            time = datetime.strptime(self.issue.fields.created, '%Y-%m-%dT%H:%M:%S.000+0800')
            str_time = utc_to_local_str(time, format='%Y-%m-%d')
            self.unresolved_issues.append({
                    'key': self.issue.key,
                    'created': str_time,
                    'issuetype': get_issuetype(self.issue),
                    'status': self.get_status().lower(),
                    'summary': self.issue.fields.summary,
                })
        self.b_solved = self.status in ['close', 'abort'] and self.unresolved_counts==0
        return self.b_solved, self.unresolved_counts, self.unresolved_issues

