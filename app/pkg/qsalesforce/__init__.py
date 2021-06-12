#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2021-06-05
#
from datetime import datetime
from simple_salesforce import Salesforce
from pkg.util.util_datetime import pick_n_days_after, utc_to_local_str

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

        ### Update date
        created_datetime = datetime.strptime(created_date, '%Y-%m-%dT%H:%M:%S.000+0000')
        deadline = pick_n_days_after(created_datetime, 60)
        created_date_str = utc_to_local_str(created_datetime, format='%Y-%m-%d')
        deadline_str = utc_to_local_str(deadline, format='%Y-%m-%d')

        ### Update Status
        sf_dict = {}
        sf_dict['case_num'] = sf_case_num
        sf_dict['researcher_email'] = email
        sf_dict['researcher_name'] = name
        sf_dict['created_date'] = created_date_str
        sf_dict['deadline'] = deadline_str

        return sf_case_num, created_date, email, name, sf_dict
    return None, None, None, None, {}
