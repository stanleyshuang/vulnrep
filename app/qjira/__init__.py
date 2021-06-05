# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2021-06-05
#
from jira import JIRA

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

def j_get_sf_case(server, username, password, jira_id):
    jira = JIRA(basic_auth=(username, password), options={'server': server})
    issue = jira.issue(jira_id)

    description = issue.fields.description
    b_need_update, name, link, others = parse_salesforce_link(description)
    if len(name):
        return name
    return None

def j_normalize_ticket(server, username, password, jira_id):
    jira = JIRA(basic_auth=(username, password), options={'server': server})
    issue = jira.issue(jira_id)

    summary = issue.fields.summary         # 'Field level security permissions'
    description = issue.fields.description
    b_need_update, name, link, others = parse_salesforce_link(description)
    print('--- Jira [{jira_id}]{summary}'.format(jira_id=jira_id, summary=summary))
    if b_need_update:
        print('--- Correct Salesforce link [{name}|{link}]'.format(name=name, link=link))
        issue.update(description = '[{name}|{link}]{others}'.format(name=name, link=link, others=others))
