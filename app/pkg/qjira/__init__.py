#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2021-06-05
#
import json
from datetime import datetime
from pkg.util.util_datetime import pick_n_days_after, utc_to_local_str
from .function import parse_salesforce_link

def j_get_sf_case_num(issue):
    print('Get SF Case Number')
    description = issue.fields.description
    b_need_update, name, link, others = parse_salesforce_link(description)
    if len(name):
        return name.strip()
    return None

def j_update_sf_data(issue, sf_case_num, created_date, researcher_email, researcher_name):
    print('Update SF Data')
    jira_id = issue.id
    summary = issue.fields.summary
    print('--- Jira [{jira_id}]{summary}'.format(jira_id=jira_id, summary=summary))

    ### Update Salseforce link, researcher information
    description = issue.fields.description
    b_need_update, case_num, link, others = parse_salesforce_link(description)
    researcher_email_index = description.find(researcher_email)
    researcher_name_index = description.find(researcher_name)
    if b_need_update or researcher_email_index<0 or researcher_name_index<0:
        print('--- Correct Salesforce link [{case_num}|{link}]'.format(case_num=case_num, link=link))
        print('---         Case Number: {case_num}, Researcher: {researcher_name} [{researcher_email}]'.format(
            case_num=case_num,
            researcher_name=researcher_name,
            researcher_email=researcher_email))
        issue.update(description = '[{case_num}|{link}]\n[{researcher_name}] [{researcher_email}]\n{others}'.format(
            case_num=case_num, 
            link=link,
            researcher_name=researcher_name,
            researcher_email=researcher_email,
            others=others))

    ### Add 'vulnerability_report' in components
    b_vulnerability_report = False
    existingComponents = []
    for component in issue.fields.components:
        existingComponents.append({"name" : component.name})
        if component.name=='vulnerability_report':
            b_vulnerability_report = True
    if not b_vulnerability_report:
        existingComponents.append({"name" : 'vulnerability_report'})
        print('--- Add Components: vulnerability_report')
        issue.update(fields={"components": existingComponents})

    ### Update date
    created_datetime = datetime.strptime(created_date, '%Y-%m-%dT%H:%M:%S.000+0000')
    deadline = pick_n_days_after(created_datetime, 60)
    created_date_str = utc_to_local_str(created_datetime, format='%Y-%m-%d')
    deadline_str = utc_to_local_str(deadline, format='%Y-%m-%d')
    # Vulnerability Reporting Date: customfield_16400
    # Release Deadline:             customfield_16401
    # Finish ETA:                   customfield_11504
    if issue.raw['fields']["customfield_16400"] != created_date_str:
        issue.update(fields={"customfield_16400": created_date_str})
        print('--- Update Vulnerability Reporting Date  {created_date_str}'.format(created_date_str=created_date_str))
    if issue.raw['fields']["customfield_16401"] != deadline_str:
        issue.update(fields={"customfield_16401": deadline_str})
        print('--- Update Release Deadline              {deadline_str}'.format(deadline_str=deadline_str))
    if issue.raw['fields']["customfield_11504"] != deadline_str:
        issue.update(fields={"customfield_11504": deadline_str})
        print('--- Update Finish ETA                    {deadline_str}'.format(deadline_str=deadline_str))

def j_update_status(issue, sf_dict, analysis_cases):
    print('Update Status')
    ### Salseforce case_num, link, researcher information
    description = issue.fields.description
    b_need_update, case_num, link, others = parse_salesforce_link(description)

    ### Update Status
    status_dict = {}
    status_dict['sf'] = sf_dict
    status_dict['sf_link'] = link
    status_dict['analysis'] = analysis_cases
    status_json = json.dumps(status_dict)

    # Status Update:                customfield_13600
    issue.update(fields={"customfield_13600": status_json})

def j_dump_data(issue):
    print('Dump Data')
    for fid in issue.raw['fields']:
        if type(issue.raw['fields'][fid]) is list:
            print('--- {fid} is a list'.format(fid=fid))
            if fid=='issuelinks':
                for issue_link in issue.raw['fields'][fid]:
                    print('        - {issue_link}'.format(issue_link=issue_link))
        elif type(issue.raw['fields'][fid]) is dict:
            print('--- {fid} is a dict'.format(fid=fid))
            if fid=='comment':
                for n, v in enumerate(issue.raw['fields'][fid]):
                    print('        - {n}:{v}'.format(n=n, v=v))
        elif issue.raw['fields'][fid]:
            print('--- {fid} {name}'.format(fid=fid, name=issue.raw['fields'][fid]))

    print('--- comment')
    comments = issue.fields.comment.comments
    for comment in comments:
        cid = comment.id
        author = comment.author.displayName
        time = comment.created
        body = comment.body.replace("\r", " ").replace("\n", " ")
        print('        - {cid}: {author} {time}\n      {body}'.format(cid=cid, author=author, time=time, body=body))

def j_find_analysis(issue):
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
    comments = issue.fields.comment.comments
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

def j_search_blocked_issues(jira, issue):
    print('Searching Blocked Issue(s)')
    b_bug_ticket_created = False
    issues = []
    if 'issuelinks' in issue.raw['fields']:
        for issue_link in issue.raw['fields']['issuelinks']:
            if 'inwardIssue' in issue_link and issue_link['type']['name'] == 'Blocks':
                blocking_issue = jira.issue(issue_link['inwardIssue']['key'])
                if blocking_issue:
                    print('--- Bug ticket is CREATED at {key}, {summary}'.format(key=blocking_issue.key, summary=blocking_issue.fields.summary))
                    b_bug_ticket_created = True
                    issues.append(blocking_issue)
    if not b_bug_ticket_created:
        print('--- Bug ticket has not been created yet')
    return b_bug_ticket_created, issues
