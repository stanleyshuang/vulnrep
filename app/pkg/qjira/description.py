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

def parse_severity_leve_in_summary(content):
    '''
    example: [INTSI000-1025][Web][Security][Medium][V3] User Account hacking -> https://license2.qnap.com (Mark Ella)
    '''
    m = re.search(r"([\[][V][1-5][\]])", content)
    if m:
        return m.group(0)
    return None

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
    