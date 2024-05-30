#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2021-06-05
#
import os
from datetime import datetime
from simple_salesforce import Salesforce
from pkg._util.util_datetime import pick_n_days_after, utc_to_local_str
from pkg._util.util_file import pgp_decrypt, extract_text_from_pdf


class SF(Salesforce):
    def invoke_action(self, action, data, method="POST", **kwargs):
        import json

        """Makes an HTTP request to an action endpoint."""
        url = "{b}actions/standard/{a}".format(
            b=self.base_url,
            a=action,
        )
        result = self._call_salesforce(method, url, data=json.dumps(data), **kwargs)

        try:
            response_content = result.json()
        # pylint: disable=broad-except
        except Exception:
            response_content = result.text

        return response_content


def sf_get_data(orgid, username, password, case_num):
    sf = Salesforce(password=password, username=username, organizationId=orgid)
    SOQL = "SELECT Id, CaseNumber, CreatedDate, ContactId, Subject, Description, Status, Root_Cause__c FROM Case WHERE CaseNumber='{case_num}'".format(
        case_num=case_num
    )
    data = sf.query(SOQL)

    '''
    print('SF data enumerating..')
    for key in data:
        print('  '+key)
        try:
            it = iter(data[key])
            print('SF data {key} enumerating..'.format(key=key))
            for k in data[key]:
                print('    '+str(k))
        except TypeError as te:
            continue
    '''

    for record in data["records"]:
        sf_case_id = record["Id"]
        sf_case_num = record["CaseNumber"]
        created_date = record["CreatedDate"]
        contact_id = record["ContactId"]
        contact = sf.Contact.get(contact_id)
        email = contact["Email"]
        name = contact["Name"]
        subject = record["Subject"]
        description = record["Description"]
        status = record["Status"]
        root_cause = record["Root_Cause__c"]

        ### Update date
        created_datetime = datetime.strptime(created_date, "%Y-%m-%dT%H:%M:%S.000+0000")
        deadline = pick_n_days_after(created_datetime, 60)
        created_date_str = utc_to_local_str(created_datetime, format="%Y-%m-%d")
        deadline_str = utc_to_local_str(deadline, format="%Y-%m-%d")

        ### Update Status
        sf_dict = {}
        sf_dict["sf_case_num"] = sf_case_num
        sf_dict["sf_case_id"] = sf_case_id
        sf_dict["researcher_email"] = email
        sf_dict["researcher_name"] = name
        sf_dict["created_date"] = created_date_str
        sf_dict["deadline"] = deadline_str
        sf_dict["subject"] = subject
        sf_dict["description"] = description
        sf_dict["status"] = status

        return sf_case_num, created_date, email, name, sf_dict
    return None, None, None, None, {}


def sf_send_email(orgid, username, password, sf_case_id, receiver, body, subject):
    sf = SF(password=password, username=username, organizationId=orgid)
    sf.invoke_action(
        "emailSimple",
        {
            "inputs": [
                {"emailAddresses": receiver, "emailBody": body, "emailSubject": subject}
            ]
        },
    )
    # 建立 EmailMessage 記錄
    try:
        email_msg = {
            "ToAddress": receiver,
            "Subject": subject,
            "TextBody": body,
            "Status": 2,
            "ParentId": sf_case_id,
        }
        sf.EmailMessage.create(email_msg)
        print("已發送回覆郵件至: ", receiver)

        print("綁定案件編號 sf_case_id: " + str(sf_case_id))
        # 綁定案件編號
        case_comment = {
            "ParentId": sf_case_id,
            "CommentBody": body,
            "IsPublished": False,
        }
        sf.CaseComment.create(case_comment)
    except Exception as e:
        print("發送回覆郵件失敗: ", e)


def sf_case_comment(orgid, username, password, sf_case_id, the_comment):
    sf = SF(password=password, username=username, organizationId=orgid)
    case_comment = {
        "ParentId": sf_case_id,
        "IsPublished": False,
        "CommentBody": the_comment,
    }
    sf.CaseComment.create(case_comment)


def sf_update_case(
    orgid, username, password, sf_case_id, subject=None, description=None, status=None, root_cause=None, root_cause_description=None
):
    sf = SF(password=password, username=username, organizationId=orgid)
    if subject:
        sf.Case.update(sf_case_id, {"Subject": subject})
    if description:
        sf.Case.update(sf_case_id, {"Description": description})
    if status:
        sf.Case.update(sf_case_id, {"Status": status})
    if root_cause:
        sf.Case.update(sf_case_id, {"Root_Cause__c": root_cause})
    if root_cause_description:
        sf.Case.update(sf_case_id, {"Description_Root_Cause__c": root_cause_description})


def sf_get_attachments(
    orgid,
    username,
    password,
    data,
    downloads,
    pgp_passphrase,
    pgp_key_path,
    parent_id,
    sf_case_num,
):
    sf = Salesforce(password=password, username=username, organizationId=orgid)

    # 查询指定 Case 编号的附件
    attachments = sf.query_all(
        "SELECT ID, Name, ContentType, Body FROM Attachment WHERE ParentId IN (SELECT Id FROM EmailMessage WHERE ParentId = '{parent_id}')".format(
            parent_id=parent_id
        )
    )

    attachment_data = []

    for record in attachments["records"]:
        attachment_id = record["Id"]
        attachment_name = record["Name"]
        attachment_type = record["ContentType"]

        # Fetch the attachment content
        attachment_url = sf.base_url + f"sobjects/Attachment/{attachment_id}/Body"
        attachment_response = sf.session.get(attachment_url, headers=sf.headers)

        if attachment_response.status_code == 200:
            attachment_content = attachment_response.content

            # Determine the download path for the attachment
            attachment_directory = os.path.join(downloads, "sf", sf_case_num)
            os.makedirs(attachment_directory, exist_ok=True)
            attachment_filepath = os.path.join(attachment_directory, attachment_name)

            with open(attachment_filepath, "wb") as file:
                file.write(attachment_content)

            # Optionally, you can perform PGP decryption here if needed
            if attachment_name.endswith((".pgp", ".gpg", ".asc")):
                status, outputfile = pgp_decrypt(
                    pgp_passphrase, pgp_key_path, attachment_filepath
                )
                if status and status.ok:
                    print(" ┌> 附件解碼： " + outputfile)
                    attachment_filepath = outputfile

            attachment_info = {
                "Id": attachment_id,
                "Name": attachment_name,
                "ContentType": attachment_type,
                "Downloaded": attachment_filepath,
            }
            print(" ┌> 下載附件： " + attachment_filepath)
            attachment_data.append(attachment_info)
        else:
            print(
                "!!! 下載失敗： ("
                + str(attachment_response.status_code)
                + ") "
                + attachment_name
            )

    return attachment_data


# under construction
def sf_get_reply_record(orgid, username, password, reply_record_name):
    sf = Salesforce(password=password, username=username, organizationId=orgid)
    """
    SOQL = "SELECT Label, QualifiedApiName FROM EntityDefinition"
    SOQL = "SELECT EntityDefinition.QualifiedApiName, QualifiedApiName, DataType FROM FieldDefinition WHERE EntityDefinition.QualifiedApiName IN ('Reply_Record__c')"
    """
    SOQL = "SELECT Replyer__c, Reply__c FROM Reply_Record__c WHERE Name='{reply_record_name}'".format(
        reply_record_name=reply_record_name
    )

    try:
        # 使用 Salesforce 查询语言（SOQL）来查询记录
        result = sf.query(SOQL)

        # 提取结果
        records = result["records"]
        for record in records:
            if record:
                return record["Replyer__c"], record["Reply__c"]

    except Exception as e:
        print(f"An error occurred: {e}")
    return None, None
