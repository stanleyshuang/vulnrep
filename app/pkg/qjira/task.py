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
from .comment import comment_parser, analysis_done_callback
from .description import parse_salesforce_link, parse_severity_leve_in_summary, severity_level_2_cvssv3_score

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
        # salesforce data
        self.sf_data = {}

        # data flags
        self.b_analysis_done = False
        self.b_verification_done = False
        self.b_apprelease_done = False
        self.b_fwrelease_done = False
        self.b_disclosure_done = False

        # status for each phase
        self.analysis_data = {}
        self.verification_data = {}
        self.apprelease_data = {}
        self.fwrelease_data = {}
        self.disclosure_data = {}
        self.bug_counts = 0 # the number of Bug issues

        # email to researcher
        self.emails = {}

    def get_sf_case_num(self):
        print('Get SF Case Number')
        description = self.issue.fields.description
        b_need_update, name, link, others = parse_salesforce_link(description)
        if len(name):
            return name.strip()
        return None

    def set_sf_data(self, created_date, researcher_email, researcher_name, sf_data):
        print('Update SF Data')
        jira_id = self.issue.id
        summary = self.issue.fields.summary
        print('--- Jira [{jira_id}]{summary}'.format(jira_id=jira_id, summary=summary))

        description = self.issue.fields.description
        b_need_update, case_num, link, others = parse_salesforce_link(description)
        
        ### Update Salesforce
        if sf_data and bool(sf_data):
            self.sf_data = sf_data
        if 'sf_link' not in self.sf_data:
            self.sf_data['sf_link'] = link

        ### Update Salseforce link, researcher information
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
                
    def set_status(self):
        print('Update Status')
        ### Salseforce case_num, link, researcher information
        description = self.issue.fields.description
        b_need_update, case_num, link, others = parse_salesforce_link(description)

        dict_customfield_13600 = {}
        ### Update Salesforce
        dict_customfield_13600['SF'] = self.sf_data

        ### Update Analysis
        dict_customfield_13600['ANALYSIS'] = self.analysis_data

        ### Update Verification
        dict_customfield_13600['VERIFICATION'] = self.verification_data

        ### Update APP Release Process
        dict_customfield_13600['APP_RELEASE_PROCESS'] = self.apprelease_data

        ### Update FW Release Process
        dict_customfield_13600['FW_RELEASE_PROCESS'] = self.fwrelease_data

        ### Update Disclosure
        dict_customfield_13600['DISCLOSURE'] = self.disclosure_data

        ### Update emails
        dict_customfield_13600['EMAILS'] = self.emails


        # Status Update: customfield_13600
        str_customfield_13600 = json.dumps(dict_customfield_13600, indent=4)
        if self.issue.raw['fields']["customfield_13600"] != str_customfield_13600:
            print('--- update Status Update (customfield_13600)')
            self.issue.update(fields={"customfield_13600": str_customfield_13600})

    def collect_analysis_result(self):
        '''
        b_analysis_done:    analysis done or not
        analysis_data:      {
                                'status': 'done' or 'on-going..',
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
            comment_parser(self, comment, ['[Security]', ['[V1]', '[V2]', '[V3]', '[V4]', '[V5]']], analysis_done_callback)

        if not self.b_analysis_done and self.get_status_name() in ['abort', 'close']:
            self.b_analysis_done = True
            self.analysis_data['status'] = 'done'
        else:
            # print('--- Analysis is on going')
            self.analysis_data['status'] = 'on-going..'

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

        if self.get_status_name() not in ['close', 'abort']:
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

    def collect_verification_result(self):
        '''
        b_verification_done:    verification True or False
        verification_data:      {   
                                    'status': 'done' or 'on-going..',
                                    'unresolved': [
                                        'key':          jira key, 'INTSI000-1033',
                                        'created':      date time in format '2021-05-13',
                                        'status':       'done', 'verified', and so on,
                                        'summary':      jira summary,
                                    ]
                                }
        '''
        # print('Find verification result')
        self.verification_data = {}
        self.bug_counts = 0

        for unresolved_issue in self.unresolved_issues:
            if unresolved_issue['issuetype']=='Bug':
                if self.bug_counts==0:
                    self.verification_data['unresolved'] = []
                self.bug_counts += 1
                self.verification_data['unresolved'].append({'key':      unresolved_issue['key'],
                                                             'created':  unresolved_issue['created'],
                                                             'status':   unresolved_issue['status'],
                                                             'summary':  unresolved_issue['summary'],
                                                            })
        if not self.b_analysis_done or len(self.verification_data)!=0 or self.bug_counts==0:
            self.b_verification_done = False
            self.verification_data['status'] = 'on-going..'
        else:
            self.b_verification_done = True
            self.verification_data['status'] = 'done'


    def collect_apprelease_result(self):
        '''
        b_apprelease_done:  apprelease True or False
        apprelease_data:    {   
                                'status': 'done' or 'on-going..',
                                'unresolved': [
                                    'key':      jira key, 'INTSI000-1033',
                                    'created':  date time in format '2021-05-13',
                                    'status':   'done', 'verified', and so on,
                                    'summary':  jira summary,
                                    'eta':      date time in format '2021-05-13',
                                ]
                            }
        '''
        # print('Find apprelease result')
        self.b_apprelease_done = True
        self.apprelease_data = {}

        for unresolved_issue in self.unresolved_issues:
            if unresolved_issue['issuetype']=='App Release Process':
                if self.b_apprelease_done:
                    self.b_apprelease_done = False
                    self.apprelease_data['unresolved'] = []
                self.apprelease_data['unresolved'].append({'key':      unresolved_issue['key'],
                                                           'created':  unresolved_issue['created'],
                                                           'status':   unresolved_issue['status'],
                                                           'summary':  unresolved_issue['summary'],
                                                           'eta':      unresolved_issue['eta'],
                                                          })
        if not self.b_apprelease_done and len(self.apprelease_data['unresolved'])>0:
            self.apprelease_data['status'] = 'on-going..'
        elif not self.b_verification_done:
            self.apprelease_data['status'] = 'not started'
        else:
            self.apprelease_data['status'] = 'done'

    def collect_fwrelease_result(self):
        '''
        b_fwrelease_done:  fwrelease True or False
        fwrelease_data:    {   
                                'status': 'done' or 'on-going..',
                                'unresolved': [
                                    'key':      jira key, 'INTSI000-1033',
                                    'created':  date time in format '2021-05-13',
                                    'status':   'done', 'verified', and so on,
                                    'summary':  jira summary,
                                    'eta':      date time in format '2021-05-13',
                                ]
                            }
        '''
        # print('Find fwrelease result')
        self.b_fwrelease_done = True
        self.fwrelease_data = {}

        for unresolved_issue in self.unresolved_issues:
            if unresolved_issue['issuetype']=='FW Release Process':
                if self.b_fwrelease_done:
                    self.b_fwrelease_done = False
                    self.fwrelease_data['unresolved'] = []
                self.fwrelease_data['unresolved'].append({'key':      unresolved_issue['key'],
                                                          'created':  unresolved_issue['created'],
                                                          'status':   unresolved_issue['status'],
                                                          'summary':  unresolved_issue['summary'],
                                                          'eta':      unresolved_issue['eta'],
                                                          })
        if not self.b_fwrelease_done and len(self.fwrelease_data['unresolved'])>0:
            self.fwrelease_data['status'] = 'on-going..'
        elif not self.b_verification_done:
            self.fwrelease_data['status'] = 'not started'
        else:
            self.fwrelease_data['status'] = 'done'

    def collect_disclosure_result(self):
        '''
        b_disclosure_done:  disclosure True or False
        disclosure_data:    {   
                                'status': 'done' or 'on-going..',
                                'disclosure': [
                                    'key':      jira key, 'INTSI000-1033',
                                    'created':  date time in format '2021-05-13',
                                    'status':   'done', 'verified', and so on,
                                ]
                            }
        '''
        # print('Find disclosure result')
        self.b_disclosure_done = True
        self.disclosure_data = {}
        self.disclosure_data['status'] = 'done'

        for unresolved_issue in self.unresolved_issues:
            if unresolved_issue['issuetype']=='Task':
                if self.b_disclosure_done:
                    self.b_disclosure_done = False
                    self.disclosure_data['status'] = 'on-going..'
                    self.disclosure_data['unresolved'] = []
                self.disclosure_data['unresolved'].append({'key':      unresolved_issue['key'],
                                                           'created':  unresolved_issue['created'],
                                                           'status':   unresolved_issue['status'],
                                                           # 'summary':  unresolved_issue['summary'],
                                                          })

    def resolved(self):
        status = self.get_status_name()
        return status in ['close', 'abort'] and self.unresolved_counts==0

    def run(self, downloads, b_update=False):
        issue_status = {}
        self.collect_unresolved_issues()
        self.collect_analysis_result()
        self.collect_verification_result()
        self.collect_apprelease_result()
        self.collect_fwrelease_result()
        self.collect_disclosure_result()
        self.create_emails_for_researcher()
 
        if self.resolved():
            author, created, status = self.get_auther_and_created_in_changlog('status', [self.get_status_name()])
            created = datetime.strptime(created, '%Y-%m-%dT%H:%M:%S.000+0800')
            str_created = utc_to_local_str(created, format='%Y-%m-%d')

            issue_status['summary'] = 'RESOLVED, {author}, {str_created}'.format(author=author, str_created=str_created)
            issue_status['author'] = author
            issue_status['latest_updated'] = str_created
            issue_status['issue_status'] = status
        else:
            issue_status['summary'] = 'NOT RESOLVED'
            issue_status['analysis'] = self.analysis_data
            issue_status['verification'] = self.verification_data
            issue_status['app_release'] = self.apprelease_data
            issue_status['fw_release'] = self.fwrelease_data
            issue_status['disclosure'] = self.disclosure_data
            issue_status['emails'] = self.emails
        print(json.dumps(issue_status, indent=4))
        
        ### update Status Update
        if b_update and self.get_sf_case_num():
            self.set_status()
        self.download_cve_jsons(downloads)

    def create_emails_for_researcher(self):
        self.emails = {}
        ### email to notify the researcher that analysis is done
        if self.b_analysis_done:
            rating = {}
            # subject
            subject = ''
            summary = self.analysis_data['summary']
            if len(summary)>1:
                subject = self.issue.fields.summary
            elif len(summary)==1:
                subject = summary[0]
            rating['subject'] = '{case_num} {subject}'.format(case_num=self.sf_data['case_num'], subject=subject)

            # receiver
            rating['receiver'] = self.sf_data['researcher_email']

            # mail_body
            mail_template = 'Hi {researcher_name}\n' \
                            'Nice to hear from you. We received your vulnerability report and the initial triage results are listed below.\n' \
                            '{vuln_analysis_statement}\n' \
                            'Do you agree with the triage results? In addition, do you have any plan to disclose the vulnerabilities?\n' \
                            'Best regards'
            vuln_analysis_statement = ''
    
            for item in summary:
                severity_level = parse_severity_leve_in_summary(item)
                low, high = severity_level_2_cvssv3_score(severity_level)
                vuln_analysis_statement += '- {case_num} {subject}\n' \
                                           'Valid, the severity level is {severity_level} ' \
                                           'which is CVSSv3 Score {low} - {high}.\n'.format(
                                                case_num=self.sf_data['case_num'], 
                                                subject=item,
                                                severity_level=severity_level,
                                                low=low,
                                                high=high)
            rating['body'] = mail_template.format(researcher_name=self.sf_data['researcher_name'],
                                                      vuln_analysis_statement=vuln_analysis_statement)
            if len(summary)>0:
                self.emails['rating'] = rating
