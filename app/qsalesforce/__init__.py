# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2021-06-05
#
from simple_salesforce import Salesforce

def get_data(orgid, username, password):
    sf = Salesforce(password=password, username=username, organizationId=orgid)
    SOQL = "SELECT Id, Email FROM Contact"
    data = sf.query(SOQL)
    for d in data['records']:
        print("{id} -- {email}".format(id=d['Id'], email=d['Email']))