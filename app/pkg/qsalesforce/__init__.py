#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2021-06-05
#
from simple_salesforce import Salesforce

def sf_get_data(orgid, username, password, case_num):
    sf = Salesforce(password=password, username=username, organizationId=orgid)
    SOQL = "SELECT CaseNumber, CreatedDate, ContactId FROM Case WHERE CaseNumber='{case_num}'".format(case_num=case_num)
    data = sf.query(SOQL)
    for d in data['records']:
        sf_case_num=d['CaseNumber']
        created_date=d['CreatedDate']
        contact_id=d['ContactId']
        contact = sf.Contact.get(contact_id)
        email=contact['Email']
        name=contact['Name']
        return sf_case_num, created_date, email, name
    return None, None, None, None
