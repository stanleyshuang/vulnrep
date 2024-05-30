#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2023-01-26
#
###############################################################################

import json

from datetime import datetime
from jira import JIRA

from pkg._mail import i_mail
from pkg._qjira.batch_common import jira_filter, cat_issues_by_researcher
from pkg._qjira.description import extract_severity_level, extract_model
from pkg._qsalesforce import sf_get_data, sf_send_email, sf_case_comment, sf_update_case
from pkg._util.util_datetime import (
    utc_to_local_str,
    local_str_to_utc,
    pick_n_days_after,
)


def make_gsheet(
    the_issue,
    qsaid,
    vanalysis,
    vtask_obj,
    vraw,
    release_raws,
    gsheet,
    apphome_data,
    apphome_downloads,
):
    update_date_str = utc_to_local_str(datetime.now(), format="%Y-%m-%d")
    jira_key = the_issue.issue.key
    print("--- update_date_str: " + update_date_str)
    print("--- jira_key: " + jira_key)

    cveid = vtask_obj.cveid
    deadline_str = the_issue.issue.raw["fields"]["customfield_16401"]
    print("--- cveid: " + cveid)
    print("--- qsaid: " + qsaid)
    print("--- deadline_str: " + deadline_str)

    if "sf_created" in vraw.json_obj["raw"] and vraw.json_obj["raw"]["sf_created"]:
        submitted_date = vraw.json_obj["raw"]["sf_created"]
    elif "triaged" in vraw.json_obj["raw"] and vraw.json_obj["raw"]["triaged"]:
        submitted_date = vraw.json_obj["raw"]["triaged"]
    else:
        submitted_date = "n/a"
    if vanalysis and vanalysis.json_obj and "validated" in vanalysis.json_obj:
        triage_date = vanalysis.json_obj["validated"]
    else:
        triage_date = "n/a"
    str_bug_num = vraw.json_obj["raw"]["bug_num"]
    str_not_affected_num = vraw.json_obj["raw"]["not_affected_num"]
    denominator = str_bug_num
    if str_not_affected_num != "0":
        denominator = "(" + denominator + "-" + str_not_affected_num + ")"

    if str_bug_num == "0":
        fixed = "n/a"
        released = "n/a"
    else:
        xbugs = vraw.json_obj["bugs"]
        fixed_bug_num = 0
        for xbug in xbugs:
            if xbug["fixed"] == "Yes":
                fixed_bug_num += 1
        released_num = int(vraw.json_obj["raw"]["at_released_num"])
        fixed = str(fixed_bug_num) + "/" + denominator
        released = str(released_num) + "/" + denominator
    print("--- submitted_date: " + submitted_date)
    print("--- triage_date: " + triage_date)
    print("--- fixed: " + fixed)
    print("--- released: " + released)

    sa_title = vraw.extract_sa_title()
    if not sa_title:
        sa_title = "n/a"
    severity_level = extract_severity_level(the_issue.issue.fields.summary)
    if not severity_level:
        severity_level = ""
    print("--- sa_title: " + sa_title)
    print("--- severity_level: " + severity_level)

    if the_issue.cve_json_url and len(the_issue.cve_json_url) > 0:
        cve_json_url = the_issue.cve_json_url
    else:
        cve_json_url = ""
    if qsaid and len(qsaid) > 0:
        sqa_url = "https://www.qnap.com/en/security-advisory/" + qsaid.lower()
    else:
        sqa_url = ""
    jira_url = "https://qnap-jira.qnap.com.tw/browse/" + jira_key
    print("--- cve_json_url: " + cve_json_url)
    print("--- sqa_url: " + sqa_url)
    print("--- jira_url: " + jira_url)

    qsa_dashboard = [
        update_date_str,
        jira_key,
        cveid,
        qsaid,
        deadline_str,
        submitted_date,
        triage_date,
        fixed,
        released,
        None, # Reviewed
        None, # Published
        sa_title,
        severity_level,
        cve_json_url,
        sqa_url,
        jira_url,
    ]
    gsheet.update_qsa_dashboard(qsa_dashboard)


def make_qsa(
    the_issue,
    qsaid,
    vtask,
    vraw,
    vanalysis,
    gsheet,
    researcher_nickname,
    data,
    downloads,
    b_dependency_resolved,
):
    from pkg._fdb.vqsa import vqsa
    from pkg._cve import cve
    from pkg._cve.json_3rdparty import json_3rdparty

    from pkg._fdb.vbountyhunter import vbountyhunter
    from pkg._fdb.vnotification_email import vnotification_email

    issuekey = the_issue.issue.key

    vnotification_email = vnotification_email(data, downloads)

    # 更新外部研究員資料
    vbountyhunter = vbountyhunter(data, downloads)
    a_row = gsheet.read_bountyhunter_json(the_issue.sf_data)
    if a_row:
        vbountyhunter.write_bountyhunter_json(a_row)

    vqsa = vqsa(data, downloads)
    origin_qsa = vqsa.load(issuekey)

    qsa = {}
    qsa = vtask.retrieve_qsa(issuekey, qsa)
    qsa = vraw.retrieve_qsa_product(issuekey, qsa)
    qsa = vanalysis.retrieve_qsa(issuekey, qsa)
    qsa = gsheet.retrieve_qsa_credit(issuekey, qsa)
    b_content_changed = vqsa.is_json_changed(issuekey, qsa)
    if b_content_changed:
        from jsondiff import diff

        the_diff = diff(origin_qsa, qsa, syntax="explicit")
        vqsa.update(issuekey, qsa)

    # make CVE ID json
    if vqsa.does_researcher_exist():
        cve_json_files = the_issue.download_attachments(
            downloads, cve.is_cve_json_filename
        )
        cve = cve(issuekey, qsa, gsheet, qsaid, the_issue.issue.fields.summary)
        cve.ensure_file_exist(data, downloads)
        cve_json_file = cve.prepare_content(cve_json_files)
        if cve_json_file:
            try:
                the_issue.remove_attachments(cve.is_cve_json_filename)
            except Exception as e:
                print("    " + str(e))
            the_attachment = the_issue.jira.add_attachment(
                issue=the_issue.issue, attachment=cve_json_file
            )
            the_issue.cve_json_url = (
                "https://qnap-jira.qnap.com.tw/secure/attachment/"
                + the_attachment.id
                + "/"
                + the_attachment.filename
            )
            print("上傳檔案：" + the_issue.cve_json_url)
    else:
        cve_json_files = the_issue.download_attachments(
            downloads, cve.is_qsa_json_filename
        )
        cve = json_3rdparty(
            issuekey, qsa, gsheet, qsaid, the_issue.issue.fields.summary
        )
        cve.ensure_file_exist(data, downloads)
        cve_json_file = cve.prepare_content(cve_json_files)
        if cve_json_file:
            try:
                the_issue.remove_attachments(cve.is_qsa_json_filename)
            except Exception as e:
                print("    " + str(e))
            the_attachment = the_issue.jira.add_attachment(
                issue=the_issue.issue, attachment=cve_json_file
            )
            the_issue.cve_json_url = (
                "https://qnap-jira.qnap.com.tw/secure/attachment/"
                + the_attachment.id
                + "/"
                + the_attachment.filename
            )
            print("上傳檔案：" + the_issue.cve_json_url)

    if vqsa.does_researcher_exist() and b_content_changed:
        # 是外部研究員通報，並且 QSA 內容改變
        print("是外部研究員通報，並且 QSA 內容改變")
        if b_dependency_resolved and not vnotification_email.is_existing(issuekey):
            # Jira BUG 全解，而且通知信還沒寄出
            print("Jira BUG 全解，而且通知信還沒寄出")
            (
                b_plan_2_disclose,
                b_request_info,
                researcher_name,
            ) = vbountyhunter.request_researcher_name(
                vqsa.researcher_email(), researcher_nickname
            )
            # qsaid = vtask.get_qsaid(issuekey)
            vnotification_email.create(
                issuekey,
                the_issue.sf_data,
                "",  # vanalysis.json_obj["summary"],
                qsaid,
                researcher_name,
                qsa,
            )
        elif not vtask.should_draft_sa(issuekey) and not vtask.should_publish_cve_id(
            issuekey
        ):
            pass
            """
            subject = '[published] ' + qsa['task']['cveid']
            body = 'QSA content updated\n資安通報後臺已完成，MITRE已通報\n' + qsa['task']['cveid'] + '\n' + issuekey + '\n--\n' + json.dumps(qsa, indent=2) + '\n--\n' + str(the_diff)
            mail = i_mail(subject, body)
            mail.send()
            """
        else:
            subject = qsa["task"]["cveid"]
            body = (
                "QSA content updated\n資安通報後臺未完成或MITRE未通報\n"
                + qsa["task"]["cveid"]
                + "\n"
                + issuekey
                + "\n--\n"
                + json.dumps(qsa, indent=2)
                + "\n--\n"
                + str(the_diff)
            )
            mail = i_mail(subject, body)
            mail.send()


def qsa_publish(
    jira,
    jql,
    gsheet,
    salesforce_orgid,
    salesforce_username,
    salesforce_password,
    apphome_data,
    apphome_downloads,
    debugobj=None,
):
    ### 收集特定 Jira Task
    todo_task_keys = jira_filter(jira, jql)

    ### 還原 Jira Tasks
    from pkg._qjira.task import analysis_task

    from pkg._cve import cve
    from pkg._fdb.analysis import analysis
    from pkg._fdb.vtask import vtask
    from pkg._fdb.analysis import analysisException
    from pkg._fdb.raw import raw

    for issuekey in todo_task_keys:
        the_issue = analysis_task(
            jira, jira.issue(issuekey, expand="changelog"), debugobj
        )
        sf_case_num = the_issue.get_sf_case_num()
        if sf_case_num:
            case_num, created_date, email, name, sf_data = sf_get_data(
                salesforce_orgid, salesforce_username, salesforce_password, sf_case_num
            )
            the_issue.set_sf_data(created_date, email, name, sf_data)

        vanalysis = analysis(apphome_data, apphome_downloads)
        vanalysis.load(issuekey)

        # 更新 Jira Task 資料
        vtask_obj = vtask(apphome_data, apphome_downloads)
        a_task_row = gsheet.read_atask_json(issuekey)
        vtask_obj.update(issuekey, a_task_row)

        vraw = raw(apphome_data, apphome_downloads)
        vraw.load(issuekey)
        release_raws = vraw.json_obj["releases"]

        # 檢查後續流程
        """
        if vtask_obj.should_draft_sa(issuekey):
            created, str_created = the_issue.get_created_n_str()
            the_issue.debuglog_r('>>> Analyzing [Task-{key}] - QSA SA DRAFT not completed'.format(key=issuekey), since=created)
        if vtask_obj.should_publish_cve_id(issuekey):
            created, str_created = the_issue.get_created_n_str()
            the_issue.debuglog_r('>>> Analyzing [Task-{key}] - QSA CVE PUBLISH not completed'.format(key=issuekey), since=created)
        if b_one_fixed:
            if vbountyhunter.is_bounty_hunter(the_issue.sf_data["researcher_email"]) and not vtask_obj.is_reward_paid(issuekey) and vanalysis.is_analysis_done():
                created, str_created = the_issue.get_created_n_str()
                the_issue.debuglog_r('>>> Analyzing [Task-{key}] - QSA PAYMENT PRINTED not completed'.format(key=issuekey), since=created)
        """

        b_one_fixed = False
        b_dependency_resolved = False
        if (
            vraw
            and "raw" in vraw.json_obj
            and vraw.json_obj["raw"]
            and "one_fixed" in vraw.json_obj["raw"]
        ):
            if vraw.json_obj["raw"]["one_fixed"] == "Yes":
                b_one_fixed = True
            if vraw.json_obj["raw"]["dependency_resolved"] == "Yes":
                b_dependency_resolved = True

        # 準備 CVE ID JSON
        # 可以更新 Jira 內容
        if "researcher_name" in the_issue.sf_data:
            nickname = the_issue.sf_data["researcher_name"]
        else:
            nickname = ""

        qsa_rec = gsheet.search_qsa_dashboard(issuekey)
        if qsa_rec and qsa_rec[3] and len(qsa_rec[3]) > 0:
            qsaid = qsa_rec[3]
            if qsaid.lower() == "n/a":
                print("gsheet-qsa 為 {qsaid} 不需處理".format(qsaid=qsaid))
                continue
            print("gsheet-qsa 有值 {qsaid}".format(qsaid=qsaid))
        else:
            """
            from pkg._fdb.vulnrep_global_config import vglobalconfig
            global_config = vglobalconfig(apphome_data, apphome_downloads)
            qsaid = global_config.availalbe_qsa_yr_id()
            """
            qsaid = gsheet.available_qsa_id()
            print("gsheet-qsa 無值，產生 {qsaid}".format(qsaid=qsaid))
            """
            if qsaid:
                global_config.set_qsaid(qsaid)
                print('更新 global config')
            """
        if b_one_fixed:
            # 至少有一張 Jira BUG 解了
            if (
                qsaid
                and len(qsaid) > 0
                and vanalysis.is_done()
                and len(vanalysis.json_obj["cveid"]) > 0
            ):  # and len(the_issue.sf_data["researcher_email"])>0:
                # 製作 CVE ID JSON
                print("弱點分析，QSA ID 指派，CVE ID 指派都完成，製作 CVE ID JSON")
                make_qsa(
                    the_issue,
                    qsaid,
                    vtask_obj,
                    vraw,
                    vanalysis,
                    gsheet,
                    nickname,
                    apphome_data,
                    apphome_downloads,
                    b_dependency_resolved,
                )
            elif (
                vanalysis.is_done()
                and "researcher_email" in the_issue.sf_data
                and len(nickname) > 0
                and not vtask_obj.is_reward_paid(issuekey)
            ):
                # 考慮要討論獎金
                print(
                    "弱點分析完成，此為外部弱點通報，考慮要討論獎金 " + nickname + "。"
                )
            else:
                print("至少一版本已解，請加速弱點分析，QSA ID 指派，CVE ID 指派。")
        else:
            print("所有版本待解，資安通報暫不發行。")

        # 產生表格
        make_gsheet(
            the_issue,
            qsaid,
            vanalysis,
            vtask_obj,
            vraw,
            release_raws,
            gsheet,
            apphome_data,
            apphome_downloads,
        )
