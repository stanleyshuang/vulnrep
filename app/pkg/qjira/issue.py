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
from .function import parse_salesforce_link

class analysis_task(i_issue):
    '''
    Jira task for vulnerabilty analysis
    '''
    def __init__(self, jira, issue):
        super(analysis_task, self).__init__(jira, issue)

    def get(self):
        return (False, u'', 'N/A', 'N/A')
        
    def set(self):
        pass

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

    def set_status(self, sf_dict, analysis_cases):
        print('Update Status')
        ### Salseforce case_num, link, researcher information
        description = self.issue.fields.description
        b_need_update, case_num, link, others = parse_salesforce_link(description)

        ### Update Status
        status_dict = {}
        status_dict['sf'] = sf_dict
        status_dict['sf_link'] = link
        status_dict['analysis'] = analysis_cases
        status_json = json.dumps(status_dict)

        # Status Update:                customfield_13600
        self.issue.update(fields={"customfield_13600": status_json})

    def search_result(self):
        '''
        b_analysis_done: analysis done or not
        analysis_cases: {
                            'summary': analysis summary,
                            'author': analyst who gave the comment
                            'created_date': date time in format '2021-05-13T22:10:45.000+0800'
                        }
        '''
        print('Find analysis result')
        b_analysis_done = False
        analysis_cases = []
        comments = self.issue.fields.comment.comments
        for comment in comments:
            cid = comment.id
            author = comment.author.displayName
            time = comment.created
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
                    b_analysis_done = True
                    analysis_case = {}
                    analysis_case['summary'] = line
                    analysis_case['author'] = author
                    analysis_case['created_date'] = time
                    analysis_cases.append(analysis_case)
        if not b_analysis_done:
            print('--- Analysis is on going')
        return b_analysis_done, analysis_cases



class vuln_bug(i_issue):
    '''
    Jira bug for vulnerabilty fixing
    '''
    def __init__(self, jira, issue):
        super(vuln_bug, self).__init__(jira, issue)

    def get(self):
        return (False, u'', 'N/A', 'N/A')
        
    def set(self):
        pass

