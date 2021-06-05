#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2021-06-05
#
from datetime import datetime
from jira import JIRA
from pkg.util.util_datetime import pick_n_days_after, utc_to_local_str

def extract_str_in_link(content):
    import re
    # regex to extract required strings
    reg_str = r"\[(.*?)\]"
    in_bracket = re.search(reg_str, content)
    if in_bracket:
        res = in_bracket.group(1).split('|')
        if not res or len(res)<2:
            return False, '', '', content
        if len(res)==2:
            return False, res[0], res[1], content[in_bracket.end():]
        return True, res[0], res[len(res)-1], content[in_bracket.end():]
    return False, '', '', content

def parse_salesforce_link(content):
    b_need_update, name, link, others = extract_str_in_link(content)
    return b_need_update, name, link, others

def j_get_sf_case_num(server, username, password, jira_id):
    jira = JIRA(basic_auth=(username, password), options={'server': server})
    issue = jira.issue(jira_id)

    description = issue.fields.description
    b_need_update, name, link, others = parse_salesforce_link(description)
    if len(name):
        return name.strip()
    return None

def j_update_sf_data(server, username, password, jira_id, sf_id, created_date, email, researcher_name):
    jira = JIRA(basic_auth=(username, password), options={'server': server})
    issue = jira.issue(jira_id)

    summary = issue.fields.summary
    print('--- Jira [{jira_id}]{summary}'.format(jira_id=jira_id, summary=summary))

    ### Update Salseforce link, researcher information
    description = issue.fields.description
    b_need_update, case_num, link, others = parse_salesforce_link(description)
    email_index = description.find(email)
    researcher_name_index = description.find(researcher_name)
    if b_need_update or email_index<0 or researcher_name_index<0:
        print('--- Correct Salesforce link [{case_num}|{link}]'.format(case_num=case_num, link=link))
        print('--- Case Number: {case_num}, Researcher: {researcher_name} [{email}]'.format(
            case_num=case_num,
            researcher_name=researcher_name,
            email=email))
        issue.update(description = '[{case_num}|{link}]\n[{researcher_name}] [{email}]\n{others}'.format(
            case_num=case_num, 
            link=link,
            researcher_name=researcher_name,
            email=email,
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
        print('--- Components: vulnerability_report')
        issue.update(fields={"components": existingComponents})

    ### Update date
    # print('created_date = ' + created_date)
    created_datetime = datetime.strptime(created_date, '%Y-%m-%dT%H:%M:%S.000+0000')
    deadline = pick_n_days_after(created_datetime, 60)
    created_date_str = utc_to_local_str(created_datetime, format='%Y-%m-%d')
    deadline_str = utc_to_local_str(deadline, format='%Y-%m-%d')
    # Vulnerability Reporting Date: customfield_16400
    # Release Deadline:             customfield_16401
    # Finish ETA:                   customfield_11504
    if issue.raw['fields']["customfield_16400"] != created_date_str:
        issue.update(fields={"customfield_16400": created_date_str})
        print('--- Vulnerability Reporting Date  {created_date_str}'.format(created_date_str=created_date_str))
    if issue.raw['fields']["customfield_16401"] != deadline_str:
        issue.update(fields={"customfield_16401": deadline_str})
        print('--- Release Deadline              {deadline_str}'.format(deadline_str=deadline_str))
    if issue.raw['fields']["customfield_11504"] != deadline_str:
        issue.update(fields={"customfield_11504": deadline_str})
        print('--- Finish ETA                    {deadline_str}'.format(deadline_str=deadline_str))
    '''
    for fid in issue.raw['fields']:
        if type(issue.raw['fields'][fid]) is list:
            print('{fid} is a list'.format(fid=fid))
        elif type(issue.raw['fields'][fid]) is dict:
            print('{fid} is a dict'.format(fid=fid))
        elif issue.raw['fields'][fid]:
            print('{fid} {name}'.format(fid=fid, name=issue.raw['fields'][fid]))
    '''