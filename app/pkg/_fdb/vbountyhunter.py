# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 2.0
# Date:     2022-04-17
#
from . import permanent_obj

class vbountyhunter(permanent_obj):
    ''' {
        "hexorxx0@gmail.com": {
            "bountyhunter1": [
                "2021-10-07",
                "Code Ninja",
                "hexorxx0@gmail.com"
            ],
            "bountyhunter2": [
                "Bangladesh ",
                "Sajibe Kanti",
                "Pren Soft",
                "Dhaka , Bangladesh",
                "Sajibe Kanti Sarkar",
                "https://www.linkedin.com/in/sajibe-kanti/",
                "Sajibekanti.cse@gmail.com",
                "+8801713607998",
                "Name : Sajibe Kanti \nAddress : 3R Villa , House : 1 , Road : 1 , Katasur , Mohammadpur , 1207 ,Dhaka \nCity : Dhaka \nZIP : 1207 \nCounty : Bangladesh \nMobile : +8801713607998",
                "BANK NAME: Bank Asia Limited\nA/C No: 60834003718\nA/C N : SAJIBE KANTI SARKAR \nBRANCH: Maijdee Court , Noakhali \nMOBILE: 01832103220\nSWIFT Code: BALBBDDH\nRouting Number: 070750214\n--\nName: Sajibe Kanti Sarkar\nRouting number: 084009519\nAccount number: 9600 0000 0056 2268\nAccount type: Checking\nAddress: TransferWise\n19 W 24th Street\nNew York NY 10010\nUnited States",
                "No",
                "bounty_hunter"
            ]
        },
    } '''
    def __init__(self, data, downloads, filename='bountyhunter.json', service='common'):
        super(vbountyhunter, self).__init__(data, downloads, filename, service)

    def add(self, sf_data):
        if sf_data is None or 'researcher_email' not in sf_data or len(sf_data['researcher_email'])==0:
            return

        key = sf_data["researcher_email"]
        row = {'bountyhunter1':
                    [sf_data["created_date"],
                     sf_data["researcher_name"], 
                     sf_data["researcher_email"],],}

        whole = self.load('global')
        if whole==None:
            whole = {}

        if key in whole:
            merged = whole[key] | row
        else:
            merged = row
        whole[key] = merged
        self.update('global', whole)

    def write_bountyhunter_json(self, row):
        BOUNTYHUNTER_EMAIL_IDX = 2
        if row is None or 'bountyhunter1' not in row or len(row['bountyhunter1'])<BOUNTYHUNTER_EMAIL_IDX or len(row['bountyhunter1'][BOUNTYHUNTER_EMAIL_IDX])==0:
            return

        whole = self.load('global')
        if whole==None:
            whole = {}

        key = row['bountyhunter1'][BOUNTYHUNTER_EMAIL_IDX]
        if key in whole:
            merged = whole[key] | row
        else:
            merged = row
        whole[key] = merged
        self.update('global', whole)

    def retrieve_profile(self, email):
        if len(email)==0:
            return None

        self.load('global')
        whole = self.get()
        if whole and email in whole and 'bountyhunter1' in whole[email]:
            BOUNTYHUNTER_EMAIL_IDX = 2
            profile = {
                'email': whole[email]['bountyhunter1'][BOUNTYHUNTER_EMAIL_IDX]
            }
        else:
            profile = {
                'email': email
            }
        if whole and email in whole and 'bountyhunter2' in whole[email]:
            BOUNTYHUNTER_COUNTRY_IDX = 3
            BOUNTYHUNTER_NAME_IDX = 4
            BOUNTYHUNTER_PAYPAL_IDX = 9
            BOUNTYHUNTER_BANK_IDX = 10
            if len(whole[email]['bountyhunter2'])>0:
                profile['country'] = whole[email]['bountyhunter2'][0]
            if len(whole[email]['bountyhunter2'])>BOUNTYHUNTER_NAME_IDX-BOUNTYHUNTER_COUNTRY_IDX:
                profile['name'] = whole[email]['bountyhunter2'][BOUNTYHUNTER_NAME_IDX-BOUNTYHUNTER_COUNTRY_IDX]
            if len(whole[email]['bountyhunter2'])>BOUNTYHUNTER_PAYPAL_IDX-BOUNTYHUNTER_COUNTRY_IDX:
                profile['paypal'] = whole[email]['bountyhunter2'][BOUNTYHUNTER_PAYPAL_IDX-BOUNTYHUNTER_COUNTRY_IDX]
            if len(whole[email]['bountyhunter2'])>BOUNTYHUNTER_BANK_IDX-BOUNTYHUNTER_COUNTRY_IDX:
                profile['bank'] = whole[email]['bountyhunter2'][BOUNTYHUNTER_BANK_IDX-BOUNTYHUNTER_COUNTRY_IDX]
        return profile

    def request_researcher_name(self, email, researcher_nickname):
        ### read bounty hunter profile
        self.load('global')
        whole = self.get()

        BOUNTYHUNTER_COUNTRY_IDX = 3
        BOUNTYHUNTER_NAME_IDX = 4
        BOUNTYHUNTER_DISCLOSURE_IDX = 13

        b_request_info = True
        b_plan_2_disclose = False
        researcher_name = researcher_nickname

        if whole and email in whole:
            if 'bountyhunter2' in whole[email] and len(whole[email]['bountyhunter2'])>0 and len(whole[email]['bountyhunter2'][BOUNTYHUNTER_COUNTRY_IDX-BOUNTYHUNTER_COUNTRY_IDX])>0:
                b_request_info = False
        if whole and email in whole and 'bountyhunter2' in whole[email]:
            if len(whole[email]['bountyhunter2'])<=BOUNTYHUNTER_NAME_IDX-BOUNTYHUNTER_COUNTRY_IDX or len(whole[email]['bountyhunter2'][BOUNTYHUNTER_NAME_IDX-BOUNTYHUNTER_COUNTRY_IDX])==0:
                researcher_name = researcher_nickname
            else:
                researcher_name = whole[email]['bountyhunter2'][BOUNTYHUNTER_NAME_IDX-BOUNTYHUNTER_COUNTRY_IDX]
            
            if len(whole[email]['bountyhunter2'])<=BOUNTYHUNTER_DISCLOSURE_IDX-BOUNTYHUNTER_COUNTRY_IDX or len(whole[email]['bountyhunter2'][BOUNTYHUNTER_DISCLOSURE_IDX-BOUNTYHUNTER_COUNTRY_IDX])==0:
                b_plan_2_disclose = True
            else:
                b_plan_2_disclose = False
        return b_plan_2_disclose, b_request_info, researcher_name

    '''
    def is_bounty_hunter(self, email):
        ### read bounty hunter profile
        self.load('global')
        whole = self.get()

        BOUNTYHUNTER_COUNTRY_IDX = 3
        BOUNTYHUNTER_ATTRIBUTE_IDX = 14

        if whole and email in whole and 'bountyhunter2' in whole[email]:
            if len(whole[email]['bountyhunter2'])>BOUNTYHUNTER_ATTRIBUTE_IDX-BOUNTYHUNTER_COUNTRY_IDX:
                if whole[email]['bountyhunter2'][BOUNTYHUNTER_ATTRIBUTE_IDX-BOUNTYHUNTER_COUNTRY_IDX]=='bounty_hunter':
                    return True
                else:
                    # the researcher is not a bounty hunter
                    return False
            else:
                # the researcher is not determined yet
                return False
        # not in the name list
        return False
    '''

    