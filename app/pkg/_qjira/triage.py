#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2023-01-04
#
###############################################################################


import os
from datetime import datetime

from pkg._fdb.analysis import analysis
from pkg._qjira.batch_common import jira_filter, jira_task_routine, earse_analysis
from pkg._qjira.task import analysis_task
from pkg._util.util_datetime import utc_to_local_str, duration_days


def triage(
    jira,
    jql,
    gsheet,
    salesforce_orgid,
    salesforce_username,
    salesforce_password,
    apphome_data,
    apphome_downloads,
    debugobj=None,
    option=None,
    researcher_email=None,
):
    ### 收集特定 Jira Task
    todo_task_keys = jira_filter(jira, jql)
    for task_key in todo_task_keys:
        ### 準備分析 Jira Task
        the_issue = analysis_task(
            jira, jira.issue(task_key, expand="changelog"), debugobj
        )

        ### 分析 Triage 資料
        if option == "update":
            """
            earse_analysis(
                task_key,
                the_issue,
                jira,
                apphome_data,
                apphome_downloads,
                debugobj,
                option,
                researcher_email,
            )
            """

            # 重新分析
            print("   重新分析")
            jira_task_routine(
                the_issue,
                salesforce_orgid,
                salesforce_username,
                salesforce_password,
                apphome_data,
                apphome_downloads,
                option,
                gsheet,
                researcher_email,
            )
        else:
            from pkg._qsalesforce import sf_get_data

            sf_data = {}
            sf_case_num = the_issue.get_sf_case_num()
            if sf_case_num:
                case_num, created_date, email, name, sf_data = sf_get_data(
                    salesforce_orgid,
                    salesforce_username,
                    salesforce_password,
                    sf_case_num,
                )
                the_issue.set_sf_data(created_date, email, name, sf_data)

        ### 更新 gsheet 資料
        labels = the_issue.issue.fields.labels
        if "triaged" in labels and "paid" not in labels:
            if the_issue.analysis is None:
                the_issue.analysis = analysis(apphome_data, apphome_downloads)
            the_issue.analysis.load(task_key)
            # 收集資訊
            date_str = utc_to_local_str(datetime.now(), format="%Y-%m-%d")
            summary = the_issue.issue.fields.summary

            analyst = "-"
            if "author" in the_issue.analysis.json_obj:
                at_index = the_issue.analysis.json_obj["author"].find("@")
                if at_index >= 0:
                    analyst = the_issue.analysis.json_obj["author"][:at_index]
                else:
                    analyst = the_issue.analysis.json_obj["author"]
            cveid = (
                the_issue.analysis.json_obj["cveid"]
                if "cveid" in the_issue.analysis.json_obj
                else "-"
            )
            severity_level = (
                the_issue.analysis.json_obj["severity_level"]
                if "severity_level" in the_issue.analysis.json_obj
                else "-"
            )
            description_score = (
                the_issue.analysis.json_obj["description"]
                if "description" in the_issue.analysis.json_obj
                else "-"
            )
            poc_score = (
                the_issue.analysis.json_obj["poc"]
                if "poc" in the_issue.analysis.json_obj
                else "-"
            )
            researcher_name = (
                the_issue.sf_data["researcher_name"]
                if "researcher_name" in the_issue.sf_data
                else "-"
            )
            researcher_email = (
                the_issue.sf_data["researcher_email"]
                if "researcher_email" in the_issue.sf_data
                else "-"
            )
            submitted_date = the_issue.issue.raw["fields"]["customfield_16400"]
            created_date = (
                the_issue.analysis.json_obj["created"]
                if "created" in the_issue.analysis.json_obj
                else "-"
            )
            validated_date = (
                the_issue.analysis.json_obj["validated"]
                if "validated" in the_issue.analysis.json_obj
                else "-"
            )
            duration = (
                the_issue.analysis.json_obj["duration"]
                if "duration" in the_issue.analysis.json_obj
                else "-"
            )
            sf_case_num = the_issue.get_sf_case_num() or "--------------"
            jira_url = "https://qnap-jira.qnap.com.tw/browse/" + task_key

            the_record = [
                date_str,
                summary,
                analyst,
                cveid,
                severity_level,
                description_score,
                poc_score,
                researcher_name,
                researcher_email,
                submitted_date,
                created_date,
                validated_date,
                duration,
                sf_case_num,
                task_key,
                jira_url,
            ]
            gsheet.update_triage(the_record)
