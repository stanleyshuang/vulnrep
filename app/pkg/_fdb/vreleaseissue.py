# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 2.0
# Date:     2022-04-17
#
from . import permanent_obj

class vreleaseissue(permanent_obj):
    ''' {
        "CMNLINKS-70": [
            "Yes",
            "2022-01-22",
            "CMNLINKS-70",
            "INTSI000-1511",
            "KazooServer",
            "4.11.22",
            "Kazoo Server",
            "",
            "4.11.22",
            "[QNAP live update (not include iOS ipa)] Verify & Release Kazoo Server 4.11.22"
        ]
    } '''
    def __init__(self, data, downloads, filename='xreleaseproc.json'):
        super(vreleaseissue, self).__init__(data, downloads, filename)

    def add(self, issuekey, raws):
        # print('    issuekey [' + issuekey + ']')
        json_objs = {}
        for raw in raws:
            # print('    release [' + raw['key'] + ']')
            if isinstance(raw, dict):
                case = []
                case.append(raw['done'])
                case.append(raw['created'])
                case.append(raw['key'])
                case.append(issuekey)
                case.append(raw['applied_model'])
                case.append(raw['build_number'])
                case.append(raw['product'])
                case.append(raw['platform'])
                case.append(raw['version_n_build'])
                case.append(raw['version_begin'])
                case.append(raw['summary'])
                json_objs[case[2]] = case

        self.update(issuekey, json_objs)

    def retrieve_qsa_product(self, issuekey, qsa):
        '''
        releaseissue_obj['product_data']
        '''
        ### 確定 qsa 中，有 releaseissue 階層
        if 'releaseissue' not in qsa:
            qsa['releaseissue'] = {}
        releaseissue_obj = qsa['releaseissue']

        ### 指定 releaseissue 階層的參數
        xreleaseproc = self.json_obj
        XRELEASEPROC_PRODUCT_IDX = 6
        for key in xreleaseproc:
            rec_data = xreleaseproc[key]
            if len(rec_data)>XRELEASEPROC_PRODUCT_IDX+2 and rec_data[0]=='Yes':
                the_product = rec_data[XRELEASEPROC_PRODUCT_IDX]
                the_platform = rec_data[XRELEASEPROC_PRODUCT_IDX+1]
                the_version = rec_data[XRELEASEPROC_PRODUCT_IDX+2]
                the_version_begin = rec_data[XRELEASEPROC_PRODUCT_IDX+3]
                
                version_data = {}
                version_data['platform'] = the_platform
                version_data['version_affected'] = '<'
                version_data['version_value'] = the_version
                version_data['version_begin'] = the_version_begin

                if 'product_data' not in releaseissue_obj:
                    releaseissue_obj['product_data'] = []
                b_updated = False
                for product in releaseissue_obj['product_data']:
                    if 'product_name' not in product:
                        product['product_name'] = the_product
                    if product['product_name']==the_product:
                        if 'version' not in product:
                            product['version'] = {}
                        if 'version_data' not in product['version']:
                            product['version']['version_data'] = []
                        if version_data not in product['version']['version_data']:
                            product['version']['version_data'].append(version_data)
                        b_updated = True
                if not b_updated:
                    releaseissue_obj['product_data'].append({
                            'product_name': the_product,
                            'version': { 'version_data': [version_data] }
                        })

        ### 將 qsa 位址回傳
        return qsa
    