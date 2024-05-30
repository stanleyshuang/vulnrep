# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 2.0
# Date:     2022-04-17
#
import os

from . import permanent_obj

class vtask(permanent_obj):
    ''' {
        "atask1": [
            "Yes",
            "Yes",
            "237834893@qq.com",
            "2021-09-02",
            "Q-202109-72525",
            "https://qnap-jira.qnap.com.tw/browse/INTSI000-1511",
            "CVE-2021-38680"
        ],
        "atask2": [
            "2021-11-28",
            "QSA-21-54",
            "2021-12-10",
            "2021-12-10",
            "2021-12-29",
        ]
    } '''
    def __init__(self, data, downloads, filename='atask.json'):
        super(vtask, self).__init__(data, downloads, filename)

    def retrieve_qsa(self, issuekey, qsa):
        '''
        task_obj['researcher_email']
        task_obj['cveid']
        '''
        ### 確定 qsa 中，有 task 階層
        if 'task' not in qsa:
            qsa['task'] = {}
        task_obj = qsa['task']

        ### 指定 task 階層的參數
        atask = self.json_obj
        if 'atask1' in atask:
            rec_data = atask['atask1']

            # EMAIL
            ATASK_EMAIL_IDX = 2
            task_obj['researcher_email'] = rec_data[ATASK_EMAIL_IDX]

            # CVE ID
            ATASK_CVEID_IDX = 6
            if len(rec_data)>ATASK_CVEID_IDX and rec_data[ATASK_CVEID_IDX] and len(rec_data[ATASK_CVEID_IDX])>0:
                task_obj['cveid'] = rec_data[ATASK_CVEID_IDX]
        if 'atask2' in atask:
            rec_data = atask['atask2']

            # QSA ID
            ATASK_SADRAFT_IDX = 7
            ATASK_QSAID_IDX = 8
            '''
            if len(rec_data)>ATASK_QSAID_IDX-ATASK_SADRAFT_IDX and len(rec_data[ATASK_QSAID_IDX-ATASK_SADRAFT_IDX])>0:
                qsa_id = rec_data[ATASK_QSAID_IDX-ATASK_SADRAFT_IDX]
            else:
                qsa_id = ''
            task_obj['qsa_id'] = qsa_id
            '''

            # CVE PUBLISH
            ATASK_CVE_PUBLISH_IDX = 11
            '''
            if len(rec_data)>ATASK_CVE_PUBLISH_IDX-ATASK_SADRAFT_IDX and len(rec_data[ATASK_CVE_PUBLISH_IDX-ATASK_SADRAFT_IDX])>0:
                cve_publish = rec_data[ATASK_CVE_PUBLISH_IDX-ATASK_SADRAFT_IDX]
            else:
                cve_publish = ''
            task_obj['cve_publish'] = cve_publish
            '''

            # URL
            '''
            task_obj['url'] = 'https://www.qnap.com/en/security-advisory/' + qsa_id.lower()
            '''

        ### 將 qsa 位址回傳
        return qsa

    @property
    def cveid(self):
        atask = self.json_obj
        if 'atask1' in atask:
            rec_data = atask['atask1']

            # CVE ID
            ATASK_CVEID_IDX = 6
            if len(rec_data)>ATASK_CVEID_IDX and rec_data[ATASK_CVEID_IDX] and len(rec_data[ATASK_CVEID_IDX])>0:
                return rec_data[ATASK_CVEID_IDX]
        return ''

    @property
    def qsaid(self):
        atask = self.json_obj
        if 'atask2' in atask:
            rec_data = atask['atask2']

            # QSA ID
            ATASK_SADRAFT_IDX = 7
            ATASK_QSAID_IDX = 8
            if len(rec_data)>ATASK_QSAID_IDX-ATASK_SADRAFT_IDX and len(rec_data[ATASK_QSAID_IDX-ATASK_SADRAFT_IDX])>0:
                return rec_data[ATASK_QSAID_IDX-ATASK_SADRAFT_IDX]
        return ''
    
    def should_draft_sa(self, issuekey):
        atask = self.json_obj
        if atask and 'atask1' in atask:
            rec_data = atask['atask1']
            # CVE ID
            ATASK_CVEID_IDX = 6
            if len(rec_data)>ATASK_CVEID_IDX and len(rec_data[ATASK_CVEID_IDX])>0:
                # CVE ID exist, need to post SA
                pass
            else:
                # No CVE ID
                return False
        else:
            # No CVE ID
            return False

        if atask and 'atask2' in atask:
            rec_data = atask['atask2']
            ATASK_SADRAFT_IDX = 7
            if len(rec_data)>ATASK_SADRAFT_IDX-ATASK_SADRAFT_IDX and len(rec_data[ATASK_SADRAFT_IDX-ATASK_SADRAFT_IDX])>0:
                # CVE ID exists, Draft done
                return False
            else:
                # CVE ID exists, but not drafting
                return True
        else:
            # CVE ID exists, but not drafting
            return True

    def should_publish_cve_id(self, issuekey):
        atask = self.json_obj
        if atask and 'atask1' in atask:
            rec_data = atask['atask1']
            # CVE ID
            ATASK_CVEID_IDX = 6
            if len(rec_data)>ATASK_CVEID_IDX and len(rec_data[ATASK_CVEID_IDX])>0:
                # CVE ID exist, need to post SA
                pass
            else:
                # No CVE ID
                return False
        else:
            # No CVE ID
            return False

        if atask and 'atask2' in atask:
            rec_data = atask['atask2']
            ATASK_SADRAFT_IDX = 7
            ATASK_CVEPUBLISH_IDX = 11
            if len(rec_data)>ATASK_CVEPUBLISH_IDX-ATASK_SADRAFT_IDX and len(rec_data[ATASK_CVEPUBLISH_IDX-ATASK_SADRAFT_IDX])>0:
                # CVE ID exists, CVE ID published
                return False
            else:
                # CVE ID exists, but CVE ID not published
                return True
        else:
            # CVE ID exists, but not CVE ID not published
            return True

    def is_reward_paid(self, issuekey):
        atask = self.json_obj
        if atask and 'atask2' in atask:
            rec_data = atask['atask2']
            ATASK_SADRAFT_IDX = 7
            ATASK_PAYMENTPRINTED_IDX = 15
            if len(rec_data)>ATASK_PAYMENTPRINTED_IDX-ATASK_SADRAFT_IDX and len(rec_data[ATASK_PAYMENTPRINTED_IDX-ATASK_SADRAFT_IDX])>0:
                # reward paid
                return True
        return False

    def get_qsaid(self, issuekey):
        atask = self.json_obj
        if atask and 'atask2' in atask:
            rec_data = atask['atask2']
            ATASK_SADRAFT_IDX = 7
            ATASK_QSAID_IDX = 8
            if len(rec_data)>ATASK_QSAID_IDX-ATASK_SADRAFT_IDX:
                return rec_data[ATASK_QSAID_IDX-ATASK_SADRAFT_IDX]
        return None
