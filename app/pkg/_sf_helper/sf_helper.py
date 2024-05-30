#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  sf_helper 2.1
# Date:     2023-09-23
#

import os
from jira import JIRA

from pkg._fdb.sf_raw import sf_raw
from pkg._mail import i_mail
from pkg._qjira.batch_common import jira_filter
from pkg._qjira.task import analysis_task
from pkg._qsalesforce import (
    sf_get_data,
    sf_case_comment,
    sf_update_case,
    sf_get_attachments,
    sf_get_reply_record,
)
from pkg._util.util_text_file import get_lines, output_text, html_2_text
from pkg._util.util_file import create_folder, pgp_decrypt


def decode_case(
    sf_case_num,
    salesforce_orgid,
    salesforce_username,
    salesforce_password,
    data,
    downloads,
    pgp_passphrase,
    pgp_key_path,
    debugobj,
):
    case_num, created_date, email, name, sf_data = sf_get_data(
        salesforce_orgid, salesforce_username, salesforce_password, sf_case_num
    )
    # debugobj.log_r(str(sf_data))

    # 如果是 PGP 加密內容，先下載成檔案並解碼。
    decrypted_content = ""
    if (
        "description" in sf_data
        and sf_data["description"].find("-----BEGIN PGP MESSAGE-----") >= 0
    ):
        the_target_file = (
            downloads + "/sf/" + sf_case_num + "/" + sf_case_num + ".txt.pgp"
        )
        create_folder(downloads + "/sf/" + sf_case_num + "/")
        idx = sf_data["description"].find("-----BEGIN PGP MESSAGE-----")
        output_text(the_target_file, sf_data["description"][idx:])
        status, outputfile = pgp_decrypt(pgp_passphrase, pgp_key_path, the_target_file)
        if status and status.ok:
            lines = get_lines(outputfile)
            for line in lines:
                decrypted_content += line

    # 更新 sf 紀錄 - new description
    if sf_data["description"].find(sf_case_num) < 0:
        if len(decrypted_content) > 0:
            decrypted_content = "{noformat}\n" + decrypted_content + "\n{noformat}\n"
        new_description = (
            "["
            + sf_case_num
            + "|https://qnap.lightning.force.com/lightning/r/Case/"
            + sf_data["sf_case_id"]
            + "/view]\n\n"
            + decrypted_content
            + "研究員報告：\n{noformat}\n"
            + sf_data["description"]
            + "\n{noformat}\n"
        )
        sf_update_case(
            salesforce_orgid,
            salesforce_username,
            salesforce_password,
            sf_data["sf_case_id"],
            description=new_description,
        )
        sf_data["description"] = new_description
    debugobj.log_r(
        "=== 弱點報告資訊 ========================================================"
    )
    debugobj.log_r(sf_data["description"])
    debugobj.log_r(
        "======================================================================="
    )
    return sf_data


def create_case(
    product_cat,
    sf_case_num,
    salesforce_orgid,
    salesforce_username,
    salesforce_password,
    jira_username,
    jira_password,
    jira_url,
    data,
    downloads,
    pgp_passphrase,
    pgp_key_path,
    debugobj,
):
    sf_data = decode_case(
        sf_case_num,
        salesforce_orgid,
        salesforce_username,
        salesforce_password,
        data,
        downloads,
        pgp_passphrase,
        pgp_key_path,
        debugobj,
    )

    ### 更新標題 sf subject ###############################
    summary_prefix_dict = {
        "qts": "[QTS]",
        "cloud": "[QNAP Cloud Service]",
        "web": "[QNAP Website]",
        "iei": "[IEI Website]",
        "quwan": "[QuWAN]",
        "amiz": "[AMIZ Cloud]",
    }

    # 確認產品名稱（版本）
    if product_cat in summary_prefix_dict:
        summary_prefix = summary_prefix_dict[product_cat]
    else:
        if product_cat[0] == "[":
            summary_prefix = product_cat
        else:
            summary_prefix = "[" + product_cat
        if summary_prefix[-1] != "]":
            summary_prefix += "]"
    summary_prefix += " "
    sf_case_num_tag = "SF:{sf_case_num}".format(sf_case_num=sf_case_num)

    # 更新 sf subject
    origin_subject = ""
    if "subject" not in sf_data or sf_data["subject"] is None:
        sf_update_case(
            salesforce_orgid,
            salesforce_username,
            salesforce_password,
            sf_data["sf_case_id"],
            subject="[" + sf_case_num_tag + "]" + summary_prefix,
        )
    elif sf_data["subject"].find(sf_case_num_tag) < 0:
        origin_subject = sf_data["subject"].replace("[", "").replace("]", "")
        sf_update_case(
            salesforce_orgid,
            salesforce_username,
            salesforce_password,
            sf_data["sf_case_id"],
            subject="[" + sf_case_num_tag + "]" + summary_prefix + " " + origin_subject,
        )

    # 调用函数以获取附件信息
    attachments = sf_get_attachments(
        salesforce_orgid,
        salesforce_username,
        salesforce_password,
        data,
        downloads,
        pgp_passphrase,
        pgp_key_path,
        sf_data["sf_case_id"],
        sf_data["sf_case_num"],
    )

    # 打印附件信息
    for attachment in attachments:
        debugobj.log_r(" ┌> Attachment ID: {id}".format(id=attachment["Id"]))
        debugobj.log_r(" ┌> FileName: {name}".format(name=attachment["Name"]))
        debugobj.log_r(
            " ┌> Content Type: {content_type}".format(
                content_type=attachment["ContentType"]
            )
        )
        debugobj.log_r(
            "*** Downloaded: {downloaded}".format(downloaded=attachment["Downloaded"])
        )

    # 存 sf_raw
    the_sf_raw = sf_raw(data, downloads)
    the_sf_raw.load(sf_data["sf_case_num"])
    the_sf_raw.update(sf_data["sf_case_num"], sf_data)

    ### Search if there is the issue created
    jira = JIRA(basic_auth=(jira_username, jira_password), options={"server": jira_url})
    jql = 'project=INTSI000 and type=Task and TEXT ~ "{sf_case_num_tag}" order by key desc'.format(
        sf_case_num_tag=sf_case_num_tag
    )
    todo_issue_keys = jira_filter(jira, jql)
    if todo_issue_keys is None or len(todo_issue_keys) == 0:
        j_summary = summary_prefix + origin_subject
        j_description = sf_data["description"].replace("\U0001F60A", "").replace("\U0001F600", "") # 這個字符會讓 Jira 當掉
        issue_dict = {
            "project": {"key": "INTSI000"},
            "summary": j_summary,
            "description": j_description,
            "issuetype": {"name": "Task"},
            "assignee": {"name": "StanleySHuang@qnap.com"},
        }
        debugobj.log_r("    summary = " + j_summary)
        # debugobj.log_r('    description = ' + j_description)
        debugobj.log_r("    sf_case_id = " + sf_data["sf_case_id"])

        ### 創建 Jira issue
        new_issue = jira.create_issue(fields=issue_dict)
        debugobj.log_r(
            "*** New issue {key} {summary} created".format(
                key=new_issue.key, summary=new_issue.fields.summary
            )
        )
        # 上傳附件
        for attachment in attachments:
            uploaded = jira.add_attachment(
                issue=new_issue, attachment=attachment["Downloaded"]
            )
            debugobj.log_r(
                " -> 上傳檔案： {id}-{filename}".format(
                    id=uploaded.id, filename=uploaded.filename
                )
            )

        # 將 Jira 資訊寫入 SF 紀錄
        the_jira_issue_url = "https://qnap-jira.qnap.com.tw/browse/" + new_issue.key
        sf_case_comment(
            salesforce_orgid,
            salesforce_username,
            salesforce_password,
            sf_data["sf_case_id"],
            the_jira_issue_url,
        )
        new_description = sf_data["description"]
        new_description = new_description.replace(
            "\n", "\n" + the_jira_issue_url + "\n", 1
        )
        sf_update_case(
            salesforce_orgid,
            salesforce_username,
            salesforce_password,
            sf_data["sf_case_id"],
            description=new_description,
            status="In Progress",
        )
        name = sf_data["researcher_name"]
        case_num = sf_data["sf_case_num"]
        submission_received = (
            "Dear  {name} \n\n"
            "We are grateful for your submission of a vulnerability report and value your contribution to enhancing our system's security. "
            "We want to update you that your report, identified by the case ID {case_num}, is currently being processed. "
            "Rest assured, we will notify you with further details promptly. "
            "Should you have any questions or require an update on the progress of your report, please do not hesitate to respond to this email. \n\n"
        ).format(name=name, case_num=case_num)
        '''
        if sf_data["description"].find("BEGIN PGP ") < 0:
            submission_received += (
                "To further enhance the security of our communication, we recommend that you use PGP encryption with your email when submitting future vulnerability reports. "
                "You can find our PGP encryption public key at https://www.qnap.com/en/security-advisories/.\n\n"
                "Thank you for your cooperation and understanding.\n\n"
            )
        '''
        submission_received += "Best regards, \n" "QNAP PSIRT"

        subject = "[v-report.received] " + sf_data["subject"]
        body = submission_received
        mail = i_mail(subject, body)
        mail.send()
        # sf_send_email(salesforce_orgid, salesforce_username, salesforce_password, sf_data['sf_case_id'], 'stanleyshuang@qnap.com', body, '[' + case_num + '] ' + sf_data['subject'])
    else:
        for issuekey in todo_issue_keys:
            debugobj.log_r("*** Issue {key} exists".format(key=issuekey))
            """
            the_issue = analysis_task(jira, jira.issue(issuekey, expand='changelog'), debugobj)
            for attachment in attachments:
                uploaded = the_issue.jira.add_attachment(issue=the_issue.issue, attachment=attachment['Downloaded'])
                debugobj.log_r(' -> 上傳檔案： {id}-{filename}'.format(id=uploaded.id, filename=uploaded.filename))
            break
            """
    """
    if m_ticket and mode=='verbose':
        m_ticket.enum_issue_fields()
    """


def upload_attachments(
    sf_case_num,
    salesforce_orgid,
    salesforce_username,
    salesforce_password,
    jira_username,
    jira_password,
    jira_url,
    data,
    downloads,
    pgp_passphrase,
    pgp_key_path,
    debugobj,
):
    case_num, created_date, email, name, sf_data = sf_get_data(
        salesforce_orgid, salesforce_username, salesforce_password, sf_case_num
    )

    # 调用函数以获取附件信息
    attachments = sf_get_attachments(
        salesforce_orgid,
        salesforce_username,
        salesforce_password,
        data,
        downloads,
        pgp_passphrase,
        pgp_key_path,
        sf_data["sf_case_id"],
        sf_data["sf_case_num"],
    )

    # 打印附件信息
    for attachment in attachments:
        debugobj.log_r(" ┌> Attachment ID: {id}".format(id=attachment["Id"]))
        debugobj.log_r(" ┌> FileName: {name}".format(name=attachment["Name"]))
        debugobj.log_r(
            " ┌> Content Type: {content_type}".format(
                content_type=attachment["ContentType"]
            )
        )
        debugobj.log_r(
            "*** Downloaded: {downloaded}".format(downloaded=attachment["Downloaded"])
        )

    # 存 sf_raw
    the_sf_raw = sf_raw(data, downloads)
    the_sf_raw.load(sf_data["sf_case_num"])
    the_sf_raw.update(sf_data["sf_case_num"], sf_data)

    ### Search if there is the issue created
    sf_case_num_tag = "SF:{sf_case_num}".format(sf_case_num=sf_case_num)
    jira = JIRA(basic_auth=(jira_username, jira_password), options={"server": jira_url})
    jql = 'project=INTSI000 and type=Task and TEXT ~ "{sf_case_num_tag}" order by key desc'.format(
        sf_case_num_tag=sf_case_num_tag
    )
    todo_issue_keys = jira_filter(jira, jql)
    if todo_issue_keys and len(todo_issue_keys) > 0:
        for issuekey in todo_issue_keys:
            print("上傳附件到 Jira " + issuekey)
            the_issue = analysis_task(
                jira, jira.issue(issuekey, expand="changelog"), debugobj
            )
            existing_files = []
            for existing_file in the_issue.issue.fields.attachment:
                existing_files.append(existing_file.filename)
            # 上傳附件
            for attachment in attachments:
                downloaded_filename = os.path.basename(attachment["Downloaded"])
                if downloaded_filename in existing_files:
                    print(downloaded_filename + " 已存在")
                    continue
                uploaded = jira.add_attachment(
                    issue=the_issue.issue, attachment=attachment["Downloaded"]
                )
                debugobj.log_r(
                    " -> 上傳檔案： {id}-{filename}".format(
                        id=uploaded.id, filename=uploaded.filename
                    )
                )


def update_reply_record(
    sf_case_num,
    salesforce_orgid,
    salesforce_username,
    salesforce_password,
    reply_record_name,
    jira_username,
    jira_password,
    jira_url,
    data,
    downloads,
    pgp_passphrase,
    pgp_key_path,
    debugobj,
):
    replyer, reply = sf_get_reply_record(
        salesforce_orgid,
        salesforce_username,
        salesforce_password,
        reply_record_name,
    )
    # 如果是 PGP 加密內容，先下載成檔案並解碼。
    decrypted_content = ""
    if reply and reply.find("-----BEGIN PGP MESSAGE-----") >= 0:
        the_target_file = (
            downloads + "/sf/" + sf_case_num + "/" + reply_record_name + ".txt.pgp"
        )
        create_folder(downloads + "/sf/" + sf_case_num + "/")
        idx = reply.find("-----BEGIN PGP MESSAGE-----")
        output_text(the_target_file, reply[idx:])
        status, outputfile = pgp_decrypt(pgp_passphrase, pgp_key_path, the_target_file)
        if status and status.ok:
            lines = get_lines(outputfile)
            for line in lines:
                decrypted_content += line
    elif reply and len(reply) > 0:
        decrypted_content = reply

    if len(decrypted_content) == 0:
        return

    # 如果內容為 HTML 轉純文字
    decrypted_content = html_2_text(decrypted_content)
    decrypted_content = decrypted_content.replace("\U0001F60A", "").replace("\U0001F600", "").replace("\U0001F642", "") # 這個字符會讓 Jira 當掉

    ### Search if there is the issue created
    sf_case_num_tag = "SF:{sf_case_num}".format(sf_case_num=sf_case_num)
    jira = JIRA(basic_auth=(jira_username, jira_password), options={"server": jira_url})
    jql = 'project=INTSI000 and type=Task and TEXT ~ "{sf_case_num_tag}" order by key desc'.format(
        sf_case_num_tag=sf_case_num_tag
    )
    todo_issue_keys = jira_filter(jira, jql)
    if todo_issue_keys and len(todo_issue_keys) > 0:
        for issuekey in todo_issue_keys:
            the_issue = analysis_task(
                jira, jira.issue(issuekey, expand="changelog"), debugobj
            )
            # 搜尋是否已公告
            comments = the_issue.issue.fields.comment.comments
            for comment in comments:
                content = comment.body
                if content.find(reply_record_name) >= 0:
                    print(reply_record_name + " 內容已存在於 " + issuekey)
                    return

            print("更新內容： " + reply_record_name + " 於 " + issuekey)
            jira.add_comment(
                the_issue.issue,
                reply_record_name
                + "\n[vauthor]["
                + replyer
                + "]\n"
                + decrypted_content,
            )


def respond(
    subcmd,
    sf_case_num,
    salesforce_orgid,
    salesforce_username,
    salesforce_password,
    data,
    downloads,
    pgp_passphrase,
    pgp_key_path,
    debugobj,
    reply_record_name=None,
):
    case_num, created_date, email, name, sf_data = sf_get_data(
        salesforce_orgid, salesforce_username, salesforce_password, sf_case_num
    )
    if subcmd == "tech_support":
        subject = "[v-report:sfmsg:tech_support] " + sf_data["subject"]
        body = (
            "** 被勒索軟體感染\n"
            "Dear {!Contact.LastName},\n\n"
            "Thank you for reaching out to us. We are sorry to hear about the ransomware infection on your NAS. We understand how frustrating and concerning this must be for you.\n"
            "To provide you with better assistance, we have recently migrated to a new support system. Therefore, we would like to invite you to create a new service ticket through the following link:\n\n"
            "https://www.qnap.com/en/support-ticket/\n\n"
            "We appreciate your patience and cooperation in this matter and look forward to helping you resolve this issue as soon as possible.\n\n"
            "Best regards,\nQNAP PSIRT\n\n"
            "** 告知客服連結\n"
            "Dear {!Contact.LastName},\n\n"
            "Thank you for submitting a vulnerability report to QNAP PSIRT. We appreciate the time and effort you have invested in reporting this issue to us. "
            "After carefully reviewing your report, we believe that Technical Support is best suited to help you resolve the issue you have identified. "
            "Our technical support colleagues have extensive experience to provide you with the necessary assistance.\n\n"
            "Please note that we have recently migrated to a new support system that requires us to collect your information in order to better assist you. "
            "Therefore, we kindly request that you resubmit your report through our new support system by creating a new service ticket at the following link: https://www.qnap.com/en/support-ticket/\n\n"
            "Thank you for your cooperation and for helping us ensure the security of our products.\n\n"
            "Best regards,\nQNAP PSIRT\n\n"
        )
        sf_update_case(
            salesforce_orgid,
            salesforce_username,
            salesforce_password,
            sf_data["sf_case_id"],
            status="Waiting Customer",
        )
        mail = i_mail(subject, body)
        mail.send()
    elif subcmd == "contact_received":
        subject = "[v-report:sfmsg:contact_received] " + sf_data["subject"]
        body = (
            "Dear {!Contact.LastName},\n\n"
            "We hope this message finds you well.\n"
            "We are writing to acknowledge the receipt of your recent email. Thank you for providing all the necessary details.\n"
            "Your contribution and engagement with our program are greatly appreciated. "
            "It's always encouraging to see such enthusiasm and expertise in the field of cybersecurity, especially from individuals who are passionate about networking and security like yourself.\n"
            "Rest assured, we have carefully noted all the information you provided and will proceed accordingly. "
            "If there are any further steps or additional information needed, we will be sure to reach out to you directly.\n"
            "Once again, thank you for your participation and for sharing your valuable insights with us. We look forward to your continued involvement in our programs.\n\n"
            "Best regards,\nQNAP PSIRT\n"
        )
        sf_update_case(
            salesforce_orgid,
            salesforce_username,
            salesforce_password,
            sf_data["sf_case_id"],
            status="In Progress",
        )
        mail = i_mail(subject, body)
        mail.send()
    elif subcmd == "info_received":
        subject = "[v-report:sfmsg:info_received] " + sf_data["subject"]
        body = (
            "Dear {!Contact.LastName},\n\n"
            "Thank you for your prompt response and for sharing the necessary information with us. "
            "Your cooperation is greatly appreciated, and we value your patience throughout this process.\n"
            "Please be assured that our team is now actively reviewing the details you've provided. "
            "We are committed to keeping you informed and will share any new developments or updates at the earliest opportunity.\n"
            "Once again, we extend our sincere thanks for your assistance.\n"
            "Warm regards,\nQNAP PSIRT\n\n"
            "\n** 提供的是銀行帳號 **\n"
            "Dear {!Contact.LastName},\n\n"
            "We noticed that you provided a bank account instead of PayPal. "
            "Please note that if you choose to receive the reward in your bank account, "
            "you will need to pay the remittance fee and any other fees required by your bank.\n"
            "For details on the applicable fees and fee amounts, please consult your bank.\n\n"
            "Best regards,\nQNAP PSIRT\n\n"
            "\n** 詢問獎金數字 **\n"
            "Dear {!Contact.LastName},\n\n"
            "We appreciate your engagement with our program. "
            "It's important to clarify that the determination of any rewards for this report will be contingent upon a comprehensive review, verification, and subsequent approval by the QNAP PSIRT committee.\n\n"
            "Warm regards,\nQNAP PSIRT\n"
        )
        sf_update_case(
            salesforce_orgid,
            salesforce_username,
            salesforce_password,
            sf_data["sf_case_id"],
            status="In Progress",
        )
        mail = i_mail(subject, body)
        mail.send()
    elif subcmd == "in_progress":
        subject = "[v-report:sfmsg:in_progress] " + sf_data["subject"]
        body = (
            "** 弱點分析階段 1\n"
            "Dear {!Contact.LastName},\n\n"
            "Thank you for your inquiry. We would like to inform you that the ticket you inquired about is currently in the triage phase, and our team is actively working on analyzing the report.\n"
            "We will keep you informed of any updates or progress on the ticket as soon as they become available. Thank you for your patience and understanding.\n\n"
            "Best regards,\nQNAP PSIRT\n\n"
            "** 弱點分析階段 2\n"
            "Dear {!Contact.LastName},\n\n"
            "Thank you for your inquiry. Currently, our team is actively working on analyzing the report. However, due to the high volume of reports we receive, the ticket is currently in the triage phase, which may take some time to complete.\n"
            "We understand your urgency and value your time. Please be assured that we are doing our best to prioritize and process all the reports as quickly as possible. We sincerely apologize for any inconvenience this may cause you.\n"
            "We will keep you informed of any updates or progress on the ticket as soon as they become available. If you have any further questions or concerns, please do not hesitate to contact us. We are here to assist you.\n"
            "Thank you for your patience and understanding.\n\n"
            "Best regards,\nQNAP PSIRT\n\n"
            "** 獎金審核階段\n"
            "Dear {!Contact.LastName},\n\n"
            "Thank you for your inquiry. We would like to inform you that the ticket you inquired about is currently in the reward proposal phase and is being reviewed by the PSIRT committee.\n"
            "Once the committee approves the reward, we will promptly notify you of the decision.\n\n"
            "Best regards,\nQNAP PSIRT\n\n"
            "** 修復驗證階段\n"
            "Dear {!Contact.LastName},\n\n"
            "Thank you for reaching out to us. We appreciate your inquiry. "
            "We would like to inform you that the ticket you inquired about is presently undergoing thorough remediation and verification procedures.\n"
            "Upon the successful completion of the verification process, the ticket will be carefully reviewed by our committee for reward consideration. "
            "We want to assure you that we are committed to keeping you informed of any developments or updates related to your inquiry.\n\n"
            "Best regards,\nQNAP PSIRT\n\n"
            "** 申訴資料分析階段\n"
            "Dear {!Contact.LastName},\n\n"
            "I hope this message finds you well. Thank you for reaching out to us with your inquiry. I would like to inform you that your clarification is currently under review by our analysis team. Rest assured that we are diligently working on it.\n"
            "We understand the importance of this matter to you, and we want to assure you that we will provide you with a prompt update as soon as there is any progress. Your patience and understanding during this process are greatly appreciated.\n"
            "Should you have any further questions or concerns, please do not hesitate to reach out to us. We value your business and are committed to ensuring your satisfaction.\n"
            "Best regards,\nQNAP PSIRT\n\n"
        )
        sf_update_case(
            salesforce_orgid,
            salesforce_username,
            salesforce_password,
            sf_data["sf_case_id"],
            status="In Progress",
        )
        mail = i_mail(subject, body)
        mail.send()
    elif subcmd == "invalid":
        subject = "[v-report:sfmsg:invalid] " + sf_data["subject"]
        body = (
            "Hi {!Contact.LastName},\n\n"
            "Thank you for taking the time to submit a vulnerability report. We greatly appreciate your efforts in helping us identify potential security issues.\n"
            "However, we regret to inform you that we are unable to accept your report due to the following reasons:\n\n"
            "- {%restrictions%}\n\n"
            "If you have any concerns regarding our assessment, please do not hesitate to reach out to us. We value your contribution to our security efforts and hope to receive more vulnerability reports from you in the future.\n\n"
            "Best regards,\nQNAP PSIRT\n\n"
            "Note: The Security Bounty Program is strictly limited to vulnerabilities found in QNAP products and services. "
            "Actions that may potentially damage or detrimentally affect QNAP servers or data are prohibited. "
            "Any vulnerability testing must not violate local laws.\n\n"
            "\n** 研究員報告客戶 myQNAPcloud domain 環境弱點 **\n"
            "- Our Security Bounty Program only accepts vulnerability reports on the officially released and latest versions of our products, applications, and services.\n"
            "- The security bounty program does not cover customers' environments, and we cannot allow vulnerability tests that may harm users' servers.\n"
            "- We would also like to clarify that the domain, {$user_domain}, belongs to our users, and we do not permit any vulnerability testing that may damage their servers.\n\n"
            "We understand that this might be disappointing for you, but please note that these restrictions are in place to ensure the security and safety of our customers' data.\n"
            "\n** 已知開源軟體漏洞 CVE ID **\n"
            "- This issue has already been reported in {%CVE ID%}. We have fixed the vulnerability in {%production version%}.\n\n"
            "\n** QNE download server 問題 **\n"
            "- Our Security Bounty Program only accepts vulnerability reports on the officially released and latest versions of our products, applications, and services.\n"
            "- This is a software download server which is not included in the Security Bounty Program.\n"
            "- The purpose of this server is to provide external users with the ability to download QNAP software.\n"
            "- The approach for the download service is the same as that of the Ubuntu archive, so we think there is no security issue."
            "  Refer to the image file: https://drive.google.com/file/d/1FTXp_uakIeKYgk7wQO3EIpT8xLzsjXu4/view?usp=share_link\n\n"
            "\n** 建議非弱點 **\n"
            "- Our program does not accept unsolicited proposals or ideas. This includes suggestions for improving present technologies, providing advice on cyber security strategy, and giving feedback on product improvements.\n"
            "- To assess and validate a reported vulnerability, we require a Proof of Concept (PoC) to demonstrate the exploit.\n"
            "- Without a PoC, it can be difficult to determine whether the issue is a security vulnerability or a specification issue.\n\n"
            "\n** account.qnap.com Email eunmeration **\n"
            "- We believe that the problem pertains to a specification rather than a security issue, as evidenced by the account creation process in Gmail and QNAP's account.qnap.com, which follow similar implementations. For instance, when a username conflict arises, Gmail informs the user that the email is already in use, as shown in this example: https://drive.google.com/file/d/12tWEKinlL5M7KWugLtb4EPCTxe4FKUXa/view?usp=sharing.\n\n"
            "\n** Alpha site **\n"
            "- Our security bounty program only covers vulnerabilities found in QNAP products and services. Unfortunately, we are unable to accept reports for vulnerabilities outside of this scope.\n"
            "- The location of the vulnerability reported is at the staging environment, which is not within the scope of our bounty program. The staging environment contains special functionalities that are used for testing purposes, and they are not considered as vulnerabilities.\n"
            "- Some of the issues you reported on the staging environment are part of the testing specifications and are not considered vulnerabilities.\n\n"
            "We understand that this news may be disappointing. However, we have these restrictions in place to ensure the security and safety of our staging environment.\n"
            "\n** CSV Injection **\n"
            "- Our Security Bounty Program only accepts vulnerability reports on the officially released and latest versions of our products, applications, and services.\n"
            "- We do not accept CSV injection vulnerabilities as part of our bounty program. Modern office software typically incorporates sufficient defense mechanisms to mitigate CSV injection risks. As a result, addressing CSV injection is not currently our program's primary focus or priority.\n\n"
            "However, we encourage you to continue participating in our program and report other types of vulnerabilities that fall within our scope. Thank you for your understanding.\n"
            "\n ** Firebase apikey 無風險 **\n"
            "- The apiKey in this configuration snippet serves to identify the Firebase project on the Google servers and does not pose a security risk if known by others. "
            "For more information, please refer to https://stackoverflow.com/questions/37482366/is-it-safe-to-expose-firebase-apikey-to-the-public.\n"
            "- In our specific case, we have implemented a lockdown mechanism that only allows HTTP requests from approved referrers to be accepted by QNAP.\n\n"
            "\n ** Google Map API 無風險 **\n"
            "- The Google Maps API key was intended to be made publicly accessible, so there's no problem with that.\n\n"
            "\n** 例外條件 **\n"
            "The security bounty program is strictly limited to vulnerabilities found in QNAP products and services. Actions that may potentially damage or detrimentally affect QNAP servers or data are prohibited. Any vulnerability testing must not violate local or Taiwanese laws.\n"
            "Vulnerability reports are not accepted if they describe or involve:\n\n"
            "- DoS (Denial of Service) attacks on QNAP or user servers.\n"
            "- Vulnerability tests that may damage QNAP’s servers or user servers.\n"
            "- Most types of brute force attacks.\n\n"
            "- Disclosure of security vulnerabilities before QNAP approval.\n"
            "- Non-critical vulnerabilities in outdated services or products.\n"
            "- Vulnerabilities only affecting outdated web browsers.\n"
            "- Vulnerabilities involving phishing, creating a fake website, or fraudulent behavior.\n"
            "- Physical attacks or social engineering.\n\n"
            "- Security vulnerability scan reports that do not include details on the impact of vulnerabilities.\n"
            "- Open-source software revealed/unrevealed vulnerability reports.\n"
            "- Attempt to activate debug mode, such as through the use of adb, with the intention of circumventing security measures in mobile apps.\n\n"
            "\n** 修改初判結果 **\n"
            "We understand that this might be disappointing for you, however, "
            "it is important to note that although we initially accept reports during the triage stage, the results may be subject to change based on additional information and input from other sources that QNAP PSIRT consults.\n\n"
            "\n** 申訴無效 (尤其是轉發為 PM 需求時) **\n"
            "Thank you for reaching out. We have carefully reviewed your inquiry internally. At present, our policy remains unchanged regarding the initial triage result. "
            "Unless the security researcher can demonstrate the exploit, our stance on this submission remains the same:\n\n"
            "\n** 解釋 invalid 沒有獎金 **\n"
            "Thank you for reaching out and inquiring about our security bounty program.\n\n"
            "The primary objective of our program is to assist our development team in identifying vulnerabilities within our systems. "
            "In order to ensure fairness and prioritize our awards, the QNAP PSIRT has established certain criteria. "
            "These criteria help us determine the reports that deserve special recognition.\n\n"
            "It is important to note that, according to the rules of our security bounty program, we are unable to provide rewards for invalid vulnerability reports. "
            "We hope you understand the rationale behind this decision.\n\n"
            "We appreciate your understanding and continued support.\n\n"
            "\n** APIKey: AIzaSyAhwiBZxXRx0kDnj4NcEuQ9BXGVcFtG_K4 **\n"
            "- The following reasons support the claim that this is not a vulnerability:\n"
            "- Google Firebase requires exposing the API key on the frontend. Please refer to https://firebase.google.com/docs/projects/api-keys?hl=en#api-keys-for-firebase-are-different\n"
            "- Even if this key is exposed, without binding it to billing, it should not have any impact.\n"
            "- The other information is mandatory for frontend.\n\n"
            "\n** APIKEY: 771f660168d3ecc003bd7910f2f6f5d9 **\n"
            "- This apiKey is provided by Algolia service and can be used on the frontend. Please refer to: https://www.algolia.com/doc/guides/security/api-keys/#search-only-api-key\n\n"
            "\n** APIKEY: OTE3MWFjNzdiNzVlOGRlZjYxY2JlMTJhMGY4ODdmOGM1MTA5ZDVjYTg4ZTEwMTZkZTJhNzQ3MDA4ZGQ0ZjJjOHRhZ0ZpbHRlcnM9 **\n"
            "- The API key is intended to be exposed and it only has the capability of querying public product information. Thus, it does not pose any potential risk of unauthorized access, data theft, malicious actions or financial loss.\n"
            "- The API key falls within designated security parameters and is deliberately provided to the frontend to enable product queries directly to the third-party search service - Algolia. Please note, this functionality is part of the design and poses no risk to the system, user data or functionality.\n\n"
            "\n** APIKEY: P6GPaFo6jy314cNHGN3PxWTGYsEN8VBg **"
            "- "
            "\n** account.qnap.com logout CFRF 規格 **\n"
            "- The current implementation of the Account Center clears all sessions and logs out upon calling https://account.qnap.com/signout, irrespective of the method used. No additional checks are performed at this point.\n"
            "- Similar to our system, Google also employs a comparable solution, where accessing https://accounts.google.com/Logout results in a complete logout.\n\n"
            "The logout implementation does not pose any security risks. However, if you happen to identify any CSRF risks in other APIs, we kindly request that you promptly notify us.\n"
            "\n** 解釋 QPKG 與瀏覽器 session management 不同的原因 **\n"
            '- We have two main session management types at account.qnap.com: "tasks of devices" and "user login via web browser", each governed by different algorithms. To see the difference, visit https://account.qnap.com/, go to "Security", and select "Logged in Devices". Here, "tasks of devices" managed sessions typically involve NAS, mobile apps, or PC utilities, and are designed to be persistent, with users able to terminate them manually.\n'
            '- The session management approach for "tasks of devices" is designed to maintain a persistent login status, ensuring uninterrupted backend communication, which is crucial for functionality. This method aligns with industry norms, as evident in widely-used applications such as Google Calendar and Gmail. We recognize your security concerns; however, effective software design frequently involves finding a middle ground between robust security measures and user-friendliness.\n\n'
            "\n** 解釋 Logged in Devices 與 Trusted Devices and Computers 不同 **\n"
            "We apologize for any inconvenience you may have confused with our UI design.\n\n"
            "- Security -> Logged in Devices: Users can find the devices which keep persistent logged in sessions. In addition, users can disconnect the sessions by remove the itmes.\n"
            '- Security -> 2-Step Verification -> Trusted Devices and Computers: The purpose of the "Trusted Devices and Computers" section is to provide users with a list where they can define devices that do not require 2-Step Verification.\n\n'
            "We hope this explanation clarifies any confusion.\n"
            "\n** 員工回報非弱點報告 **\n"
            "謝謝提交這個問題。經我們分析，此議題與 PSIRT 處理的資安類型比較不同。經過我們詢問，此類問題適合提交至另一個 Teams channel:\n\n"
            "https://teams.microsoft.com/l/channel/19%3a42e997c07e3e47f5b2292544a21b1928%40thread.tacv2/Feedback%2520%25E5%2595%258F%25E9%25A1%258C%25E5%259B%259E%25E5%25A0%25B1?groupId=603fb363-c149-4ae0-aa68-7fa9787b4749&tenantId=6eba8807-6ef0-4e31-890c-a6ecfbb98568\n\n"
            "如果由我們轉介，Teams Channel 上的提交人員會有點 confused，所以麻煩您重新此提交報告，以利後續流程。\n\n"
        )
        sf_update_case(
            salesforce_orgid,
            salesforce_username,
            salesforce_password,
            sf_data["sf_case_id"],
            status="Waiting Customer",
        )
        mail = i_mail(subject, body)
        mail.send()
    elif subcmd == "more_info":
        subject = "[v-report:sfmsg:more_info] " + sf_data["subject"]
        body = (
            "Hi {!Contact.LastName},\n\n"
            "Thank you very much for submitting a vulnerability report.\n\n"
            "We have examined the report and would like to learn some more details. Could you help us clarify the following?\n\n"
            "{%quote researcher’s description(s). And a question for more information or selections to pick%}\n\n"
            "Best regards,\nQNAP PSIRT\n"
            "\n** 無 POC **\n"
            "Dear {!Contact.LastName},\n\n"
            "We appreciate your submission of a vulnerability report.\n"
            "After a thorough review of your report, we would greatly appreciate your assistance in providing additional details. Specifically, we kindly request clarification on the following points:\n\n"
            "Your submitted vulnerability report currently lacks actionable steps or a valid Proof of Concept (POC). Without this critical information, we are unable to consider it as an eligible case. Could you please furnish the necessary details to enable us to proceed with our further analysis?\n\n"
            "We sincerely value your cooperation in helping us enhance the security of our products and services.\n\n"
            "Best regards,\n"
            "QNAP PSIRT"
        )
        mail = i_mail(subject, body)
        mail.send()
    elif subcmd == "not_reproduced":
        subject = "[v-report:sfmsg:not_reproduced] " + sf_data["subject"]
        body = (
            "Hi {!Contact.LastName},\n\n"
            "Thank you very much for submitting a vulnerability report.\n"
            "Unfortunately, we have not been able to reproduce the vulnerability issue you reported.\n"
            "Could you provide us some more details? If possible, a screen video recording would be greatly appreciated.\n\n"
            "Best regards,\nQNAP PSIRT\n\n"
            "\n** 繞過 MFA in account.qnap.com **\n"
            "- Please note that before proceeding, it's important to verify that there are no entries in Trusted Devices and Computers. You can refer to the screenshot provided below for guidance:\n\n"
            "https://drive.google.com/file/d/1QukD5d1fllkAMwcOtkPAiydSAbGNZzON/view?usp=share_link\n\n"
            "It's worth noting that if you used the devices to demo, the service would bypass the 2-Step Verification process.\n"
        )
        mail = i_mail(subject, body)
        mail.send()
    elif subcmd == "redundant":
        subject = "[v-report:sfmsg:redundant] " + sf_data["subject"]
        body = (
            "Hi {!Contact.LastName},\n\n"
            "Thank you very much for submitting a vulnerability report.\n"
            "After internal assessment we have determined that the vulnerability you reported has already been described in an earlier report:\n\n"
            "{%vulnerability report%}\n\n"
            "The earlier report was created on {%date time%}, whereas your report was created on {%date time%}. Unfortunately, "
            "that means your report is not eligible for a reward.\n\n"
            "We very much appreciate your research and look forward to seeing more vulnerability reports from you.\n\n"
            "Best regards,\nQNAP PSIRT"
        )
        sf_update_case(
            salesforce_orgid,
            salesforce_username,
            salesforce_password,
            sf_data["sf_case_id"],
            status="Waiting Customer",
        )
        mail = i_mail(subject, body)
        mail.send()
    elif subcmd == "paid":
        subject = "[v-report:sfmsg:paid] " + sf_data["subject"]
        body = (
            "Dear {!Contact.LastName},\n\n"
            "Thank you for sending the DocuSign documents. "
            "We're processing your reward, and payment will be completed within 8 weeks. Your patience is greatly appreciated.\n\n"
            "Best regards,\nQNAP PSIRT\n\n"
        )
        sf_update_case(
            salesforce_orgid,
            salesforce_username,
            salesforce_password,
            sf_data["sf_case_id"],
            root_cause="Others",
            root_cause_description='vulnerability report accepted',
        )
        sf_update_case(
            salesforce_orgid,
            salesforce_username,
            salesforce_password,
            sf_data["sf_case_id"],
            status="Resolved",
        )
        mail = i_mail(subject, body)
        mail.send()
    elif subcmd == "intro":
        subject = "[v-report:sfmsg:intro] " + sf_data["subject"]
        body = (
            "Dear {!Contact.LastName},\n\n"
            "Thank you for reaching out to us and bringing this potential security concern to our attention. "
            "We appreciate your commitment to responsible disclosure and your efforts in contributing to the security and privacy of our users.\n\n"
            "At QNAP, we highly value the collaboration with security researchers and take security matters seriously. "
            "We have a dedicated Security Bounty Program in place to encourage responsible disclosure, and we are pleased to inform you about the details of our program.\n\n"
            "Our Security Bounty Program details, including the scope, reporting procedures, and reward criteria, can be found on our official website at: \n\n"
            "        https://www.qnap.com/en/security-bounty-program\n\n"
            "On this page, you will find comprehensive information regarding the program, as well as instructions on how to report vulnerabilities and the rewards you may qualify for. "
            "We are committed to fostering a positive relationship with the security community, and we encourage you to review the provided details.\n\n"
            "If you have any additional questions or need further clarification, please feel free to reach out to us through the email address specified on the Security Bounty Program page.\n\n"
            "We sincerely appreciate your dedication to responsible disclosure and look forward to your continued collaboration in enhancing the security of our products and services. "
            "Your contribution is invaluable in ensuring a safer digital environment for our users.\n\n"
            "Thank you again for your diligence and commitment to security.\n\n"
            "Best regards,\nQNAP PSIRT\n\n"
        )
        sf_update_case(
            salesforce_orgid,
            salesforce_username,
            salesforce_password,
            sf_data["sf_case_id"],
            status="Waiting Customer",
        )
        mail = i_mail(subject, body)
        mail.send()
    elif subcmd == "decode":
        if sf_case_num:
            decode_case(
                sf_case_num,
                salesforce_orgid,
                salesforce_username,
                salesforce_password,
                data,
                downloads,
                pgp_passphrase,
                pgp_key_path,
                debugobj,
            )
        else:
            debugobj.log_r("!!! sf_case_num is None")
    else:
        print("SFMSG: sub-command unknown..")
