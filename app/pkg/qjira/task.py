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
        self.analysis_data = {}

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

    def collect_analysis_result(self):
        '''
        b_analysis_done:  analysis done or not
        analysis_data:  {
                            'author': analyst who gave the comment,
                            'created': date time in format '2021-05-13',
                            'summary': [analysis summary],
                        }
        '''
        # print('Find analysis result')
        self.b_analysis_done = False
        self.analysis_data = {}
        self.analysis_data['summary'] = []
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
                    if not self.b_analysis_done:
                        self.b_analysis_done = True
                        self.analysis_data['status'] = 'done'
                        self.analysis_data['author'] = author
                        self.analysis_data['created'] = utc_to_local_str(time, format='%Y-%m-%d')
                    self.analysis_data['summary'].append(line)
        if not self.b_analysis_done and self.get_status_name()=='abort':
            self.b_analysis_done = True
            self.analysis_data['status'] = 'done'
        if not self.b_analysis_done:
            # print('--- Analysis is on going')
            self.analysis_data['status'] = 'on-going..'
        return self.b_analysis_done, self.analysis_data

    def run(self, downloads, b_update=False):
        '''
        b_solved:           True or False
        unresolved_counts:  The number of unsolved issues
        unresolved_issues:  [{
                                'key':      jira key
                                'summary':  jira summary,
                                'created':  date time in format '2021-05-13',
                                'eta':      date time in format '2021-05-13',
                            }]
        '''
        issue_status = {}
        self.collect_analysis_result()
        self.collect_unresolved_issues()

        author, created, status = self.get_auther_and_created_in_changlog('status', [self.get_status_name()])
        created = datetime.strptime(created, '%Y-%m-%dT%H:%M:%S.000+0800')
        self.str_created = utc_to_local_str(created, format='%Y-%m-%d')

        if status not in ['close', 'abort']:
            self.unresolved_counts += 1
            time = datetime.strptime(self.issue.fields.created, '%Y-%m-%dT%H:%M:%S.000+0800')
            str_time = utc_to_local_str(time, format='%Y-%m-%d')
            self.unresolved_issues.append({
                    'key': self.issue.key,
                    'created': str_time,
                    'issuetype': get_issuetype(self.issue),
                    'status': self.get_status_name(),
                    'summary': self.issue.fields.summary,
                })
        self.b_solved = status in ['close', 'abort'] and self.unresolved_counts==0

        self.download_cve_jsons(downloads)
        if b_solved:
            issue_status['summary'] = 'RESOLVED, {author}, {str_created}'.format(author=self.author, str_created=self.str_created)
        else:
            issue_status['summary'] = 'NOT RESOLVED'
            issue_status['analysis'] = self.analysis_data

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
            issue_status['issue_status'] = status

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
        dict_customfield_13600['ANALYSIS'] = self.analysis_data

        if unsolved_data and bool(unsolved_data):
            dict_customfield_13600['STATUS'] = unsolved_data

        # Status Update: customfield_13600
        str_customfield_13600 = json.dumps(dict_customfield_13600, indent=4)
        if self.issue.raw['fields']["customfield_13600"] != str_customfield_13600:
            print('--- update Status Update (customfield_13600)')
            self.issue.update(fields={"customfield_13600": str_customfield_13600})

    def collect_unresolved_issues(self):
        from .bug import vuln_bug

        if self.b_unresolved_run:
            return

        self.b_unresolved_run = True
        self.unresolved_counts = 0
        self.unresolved_issues = []

        self.search_blocked()
        ### enumerate blocked issues and find bugs in the anslysis task
        for blocked_issue in self.blocked_issues:
            if get_issuetype(blocked_issue) == 'Bug':
                the_bug = vuln_bug(self.jira, blocked_issue)
                the_bug.collect_unresolved_issues()
                self.unresolved_counts += the_bug.unresolved_counts
                self.unresolved_issues.extend(the_bug.unresolved_issues)
