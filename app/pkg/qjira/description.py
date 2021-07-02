#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2021-06-05
#
### common functions
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

### specific funstions
def parse_salesforce_link(content):
    b_need_update, name, link, others = extract_str_in_link(content)
    return b_need_update, name, link, others
    