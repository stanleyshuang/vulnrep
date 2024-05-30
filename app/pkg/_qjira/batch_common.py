#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2023-01-26
#
###############################################################################

import os
from pkg._qjira.task import analysis_task
from pkg._qsalesforce import sf_get_data


def jira_filter(jira, jql):
    ### 收集特定 Jira issues
    todo_issue_keys = set()
    maxResults = 50
    got = maxResults
    total = 0
    while got == maxResults:
        print("    TOTAL issues: [" + str(total) + "] on JQL:[" + jql + "]")
        issues = jira.search_issues(jql, startAt=total, maxResults=maxResults)
        for an_issue in issues:
            todo_issue_keys.add(an_issue.key)
        got = len(issues)
        total += got
    return todo_issue_keys


def cat_issues_by_researcher(
    jira,
    todo_task_keys,
    salesforce_orgid,
    salesforce_username,
    salesforce_password,
    debugobj=None,
    researcher_email=None,
):
    """
    {   email:  {
            'profile': profile,
            'issues': issues,      # list
            'rewards': rewards     # key: reward
        }
    }
    """
    ### 依照 researcher email 分類 Jira Tasks
    the_researcher_issues = {}
    for issuekey in todo_task_keys:
        the_issue = analysis_task(
            jira, jira.issue(issuekey, expand="changelog"), debugobj
        )
        ### get and set SF data
        case_num, created_date, email, name = None, None, None, None
        sf_data = {}
        sf_case_num = the_issue.get_sf_case_num()
        if sf_case_num:
            case_num, created_date, email, name, sf_data = sf_get_data(
                salesforce_orgid, salesforce_username, salesforce_password, sf_case_num
            )
            if email is None:
                # print('{key}: no email data'.format(key=the_issue.issue.key))
                continue
            if researcher_email and researcher_email != email:
                # print('{key}: email [{email}] not match'.format(key=the_issue.issue.key, email=email))
                continue
        else:
            # print('{key}: SF not found'.format(key=the_issue.issue.key))
            continue
        the_issue.set_sf_data(created_date, email, name, sf_data)
        if email not in the_researcher_issues:
            the_researcher_issues[email] = {"issues": []}
        a_researcher_issues = the_researcher_issues[email]["issues"]
        a_researcher_issues.append(the_issue)
    return the_researcher_issues


def jira_task_routine(
    the_issue,
    salesforce_orgid,
    salesforce_username,
    salesforce_password,
    data,
    downloads,
    option,
    gsheet,
    assignee,
):
    from pkg._fdb.vtask import vtask
    from pkg._fdb.vbountyhunter import vbountyhunter
    from pkg._fdb.vfinding_response import vfinding_response
    from pkg._fdb.vnotification_email import vnotification_email
    from pkg._fdb.analysis import analysisException
    from pkg._fdb.raw import raw

    vtask = vtask(data, downloads)
    vbountyhunter = vbountyhunter(data, downloads)
    vfinding_response = vfinding_response(data, downloads)
    vnotification_email = vnotification_email(data, downloads)
    vraw = raw(data, downloads)

    b_update = option == "update"
    ### get and set SF data
    case_num = None
    created_date = None
    email = None
    name = None
    sf_data = {}
    sf_case_num = the_issue.get_sf_case_num()
    if sf_case_num:
        case_num, created_date, email, name, sf_data = sf_get_data(
            salesforce_orgid, salesforce_username, salesforce_password, sf_case_num
        )
        the_issue.set_sf_data(created_date, email, name, sf_data)
    if assignee:
        the_issue.set_assignee(assignee)
    try:
        raw, bug_raws, release_raws = the_issue.check(
            the_issue, the_issue, data, downloads, b_update=b_update
        )
    except analysisException as error:
        if str(error) == "non-3rd-party-multi-CVE-IDs":
            subject = "[{issuekey}] is not 3rd-party: split CVE IDs".format(
                issuekey=the_issue.issue.key
            )
            body = "as title."
            mail = i_mail(subject, body)
            mail.send()
        return

    raw_obj = {"raw": raw, "bugs": bug_raws, "releases": release_raws}
    vraw.update(the_issue.issue.key, raw_obj)
    vraw.dump_bugs()
    vraw.dump_raw()

    # 更新 Jira Task 資料
    if b_update and gsheet and vtask:
        a_task_row = gsheet.read_atask_json(the_issue.issue.key)
        vtask.update(the_issue.issue.key, a_task_row)
        gsheet.a_task(the_issue.issue, raw)
        atask_json = gsheet.compose_atask_json(the_issue.issue.key, raw)
        vtask.update(the_issue.issue.key, atask_json)

    # 更新外部研究員資料
    if b_update and gsheet and vbountyhunter:
        a_row = gsheet.read_bountyhunter_json(the_issue.sf_data)
        if a_row:
            vbountyhunter.write_bountyhunter_json(a_row)
        gsheet.update_researcher(the_issue.sf_data)

    # 送弱點確認信
    if b_update:
        the_issue.make_finding_response(
            vfinding_response, vbountyhunter, data, downloads
        )
    return None


def jira_tasks_routine(
    jira,
    jql,
    debugobj,
    salesforce_orgid,
    salesforce_username,
    salesforce_password,
    data,
    downloads,
    option,
    gsheet,
    assignee,
):
    todo_jira_keys = jira_filter(jira, jql)
    for issuekey in todo_jira_keys:
        the_issue = analysis_task(
            jira, jira.issue(issuekey, expand="changelog"), debugobj
        )
        jira_task_routine(
            the_issue,
            salesforce_orgid,
            salesforce_username,
            salesforce_password,
            data,
            downloads,
            option,
            gsheet,
            assignee,
        )


def earse_analysis(
    task_key,
    the_issue,
    jira,
    apphome_data,
    apphome_downloads,
    debugobj=None,
    option=None,
    researcher_email=None,
):
    # 清除資料
    print("   清除資料")
    # 刪除 label triaged
    the_issue.remove_label("triaged")
    # 刪除暫存分析資料
    files = ["analysis.json", "validation_email.json", "qsa.json"]
    for file in files:
        filepath = apphome_downloads + "/jira/" + task_key + "/" + file
        if os.path.isfile(filepath):
            print("    REMOVE: " + filepath)
            os.remove(filepath)
    # 刪除公告
    comments = the_issue.issue.fields.comment.comments
    for comment in comments:
        content = comment.body
        if content.find("[gpt_finding_response]") >= 0:
            print("刪除公告 " + str(comment.id))
            comment_to_delete = jira.comment(the_issue.issue.id, comment.id)
            comment_to_delete.delete()
