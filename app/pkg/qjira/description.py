#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2021-06-05
#
###############################################################################
### common functions
import re

def extract_str_in_link(content):
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

###############################################################################
### specific funstions
def parse_salesforce_link(content):
    b_need_update, name, link, others = extract_str_in_link(content)
    return b_need_update, name, link, others

def extract_severity_level(content):
    '''
    example:    [INTSI000-1025][Web][Security][Medium][V3] User Account hacking -> https://license2.qnap.com (Mark Ella)
    return:     [V3]
    '''
    m = re.search(r"([\[][V][1-5][\]])", content)
    if m:
        return m.group(0)
    return None

def extract_cveid(content):
    '''
    example:    [QPKG][Security][Medium][V3] Exposure of Sensitive Information in CloudLink - CVE-2021-28815 (xxyantixx)
    return:     CVE-2021-28815
    '''
    m = re.search(r"(CVE-\d{4}-\d{4,7})", content)
    if m:
        return m.group(0)
    return None

def extract_sa_title(content):
    '''
    example:     INTSI000-732[QPKG][Security][Medium][V3] Exposure of Sensitive Information in CloudLink - CVE-2021-28815 (xxyantixx)
    return:     Exposure of Sensitive Information in CloudLink
    '''
    satitle = content
    # print('')
    # print(satitle)
    ### (researcher_name)
    reg_tails = [r"\(.*\)", r"CVE-\d{4}-\d{4,7}"]
    for reg_tail in reg_tails:
        m2 = re.search(reg_tail, satitle)
        if m2:
            idx_tail = satitle.find(m2.group(0))
            satitle = satitle[0:idx_tail]
            # print(satitle)

    reg_heads = [r"\[V[12345]\](.*)", r"\[Security\](.*)", r"INTSI\d{3}-\d{4}(.*)"]
    for reg_head in reg_heads:
        m1 = re.search(reg_head, satitle)
        if m1:
            satitle = m1.group(1)
            # print(satitle)

    satitle = satitle.strip(' -')
    # print(satitle)
    return satitle

def severity_level_2_cvssv3_score(severity_level):
    severity2cvss = { '[V1]': ['0.0', '1.9'],
                      '[V2]': ['2.0', '3.9'],
                      '[V3]': ['4.0', '6.9'],
                      '[V4]': ['7.0', '8.9'],
                      '[V5]': ['9.0', '10.0'],
    }
    if severity_level in severity2cvss:
        return severity2cvss[severity_level][0], severity2cvss[severity_level][1]
    return None, None
    