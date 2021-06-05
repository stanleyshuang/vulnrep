# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2021-06-05
#
from simple_salesforce import Salesforce

def sf_get_data(orgid, username, password, case_num):
    sf = Salesforce(password=password, username=username, organizationId=orgid)
    SOQL = "SELECT CaseNumber, CreatedDate FROM Case WHERE CaseNumber='{case_num}'".format(case_num=case_num)
    print(SOQL)
    data = sf.query(SOQL)
    for d in data['records']:
        print("{id} - {created_date}".format(id=d['CaseNumber'], created_date=d['CreatedDate']))