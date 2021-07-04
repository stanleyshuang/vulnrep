#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2021-06-05
#
from datetime import datetime

###############################################################################
### common functions
def content_filter(content, filters, b_op_and=True):
    if b_op_and:
        for filter in filters:
            if type(filter) is str:
                if content.find(filter)<0:
                    return False
            elif type(filter) is list:
                b_found = content_filter(content, filter, not b_op_and)
                if not b_found:
                    return False
        return True
    for filter in filters:
        if type(filter) is str:
            if content.find(filter)>=0:
                return True
        elif type(filter) is list:
            b_found = content_filter(content, filter, not b_op_and)
            if b_found:
                return True
    return False

def comment_parser(the_obj, comment, filters, callback):
    from datetime import datetime
    cid = comment.id
    author = comment.author.displayName
    time = datetime.strptime(comment.created, '%Y-%m-%dT%H:%M:%S.000+0800')
    body = comment.body
    lines = body.split('\n')
    for line in lines:
        if content_filter(line, filters):
            # print('--- Analysis is DONE as {line}'.format(line=line))
            callback(the_obj, cid, author, time, line)

###############################################################################
### specific funstions
def analysis_done_callback(the_obj, cid, author, time, line):
    from pkg.util.util_datetime import utc_to_local_str
     # print('--- Analysis is DONE as {line}'.format(line=line))
    if not the_obj.b_analysis_done:
        the_obj.b_analysis_done = True
        the_obj.analysis_data['status'] = 'done'
        # the_obj.analysis_data['author'] = author
        created_time = datetime.strptime(the_obj.issue.fields.created, '%Y-%m-%dT%H:%M:%S.000+0800')
        str_created_time = utc_to_local_str(created_time, format='%Y-%m-%d')
        the_obj.analysis_data['created'] = str_created_time
        the_obj.analysis_data['done'] = utc_to_local_str(time, format='%Y-%m-%d')
    the_obj.analysis_data['summary'].append(line)

def qsa_callback(the_obj, cid, author, time, line):
    from .description import extract_cveid, extract_pf_pt_ver
    cveid = extract_cveid(line)
    idx = line.find('[SAID]:')
    if idx>=0:
        sqa_id = line[idx+len('[SAID]:'):].strip()
        the_obj.qsa[cveid]['qsa_id'] = sqa_id
        the_obj.qsa[cveid]['url'] = 'https://www.qnap.com/en/security-advisory/' + sqa_id.lower()
        return

    idx = line.find('[FIX]:')
    if idx>=0:
        product = ''
        platform = ''
        version = ''

        version_list = extract_pf_pt_ver(line)
        if len(version_list)==3:
            product = version_list[1]
            platform = version_list[0]
            version = version_list[2]
        elif len(version_list)<2:
            product = ''
            platform = ''
            version = ''
        else:
            product = version_list[0]
            platform = ''
            version = version_list[1]

        the_obj.qsa[cveid]['product_name'] = product
        if 'version_data' not in the_obj.qsa[cveid]:
            the_obj.qsa[cveid]['version_data'] = []

        version_data = {}
        version_data['platform'] = platform
        version_data['version_affected'] = '<'
        version_data['version_value'] = version
        the_obj.qsa[cveid]['version_data'].append(version_data)

    idx = line.find('[CREDIT]:')
    if idx>=0:
        credit = line[idx+len('[CREDIT]:'):].strip()
        the_obj.qsa[cveid]['credit'] = credit
