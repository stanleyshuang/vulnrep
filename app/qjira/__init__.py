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
        if not res or len(res)<=2:
            return '', '', content
        return res[0], res[len(res)-1], content[in_bracket.end():]
    return '', '', content

def parse_salesforce_link(content):
    name, link, others = extract_str_in_link(content)
    return name, link, others

def normalize_ticket(server, username, password, jira_id):
    jira = JIRA(basic_auth=(username, password), options={'server': server})

    issue = jira.issue(jira_id)
    summary = issue.fields.summary         # 'Field level security permissions'
    description = issue.fields.description
    name, link, others = parse_salesforce_link(description)
    print('--- Jira [{jira_id}]{summary}'.format(jira_id=jira_id, summary=summary))
    if len(name) > 0 and len(link) > 0:
        print('--- Correct Salesforce link [{name}|{link}]'.format(name=name, link=link))
        issue.update(description = '[{name}|{link}]{others}'.format(name=name, link=link, others=others))
