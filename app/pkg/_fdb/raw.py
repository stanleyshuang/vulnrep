# -*- coding: utf-8 -*-
#
# Author:   Stanley Huang
# Project:  vulnrep 2.0
# Date:     2022-08-14
#
from datetime import datetime
from dateutil import tz

from pkg._qjira.description import extract_model, extract_sa_title
from pkg._util.util_datetime import local_to_local_str, local_str_to_local, duration_days

from . import permanent_obj, permanent_objException

class rawException(permanent_objException):
    pass


class raw(permanent_obj):
    def __init__(self, data, downloads, filename='_raw.json'):
        super(raw, self).__init__(data, downloads, filename)

    def retrieve_qsa_product(self, issuekey, qsa):
        qsa = self.retrieve_qsa_product_in_releases(issuekey, qsa)
        qsa = self.retrieve_qsa_product_in_bugs(issuekey, qsa)
        return qsa
    
    @staticmethod
    def get_product_name(summary):
        model, the_product, the_version_begin=extract_model(summary)
        model_display = {
            'qts': 'QTS',
            'quts hero': 'QuTS hero',
            'qutscloud': 'QuTScloud',
            'qne': 'QNE',
            'qvp': 'QVP (QVR Pro appliances)',
            'qvr': 'QVR',
            'qes': 'QES'
        }
        if model in model_display:
            return model_display[model], the_version_begin
        elif the_product and len(the_product)>0:
            return the_product, the_version_begin
        return None, the_version_begin
    
    @staticmethod
    def make_product_list(summary, products):
        product_name, the_version_begin = raw.get_product_name(summary)
        if product_name not in products:
            products.append(product_name)
        return products

    def extract_sa_title(self):
        sa_title = ''
        if 'summary' in self.json_obj['raw'] and self.json_obj['raw']['summary'].find('3rd-party')>=0:
            sa_title = extract_sa_title(self.json_obj['raw']['summary'])
        elif len(self.json_obj['bugs']) > 0:
            xbugs = self.json_obj['bugs']
            products = []
            for bug in xbugs:
                products = raw.make_product_list(bug['summary'], products)
            
            # 定義順序列表
            order = ["QTS", "QuTS hero", "QuTScloud", "QNE", "QVP (QVR Pro appliances)", "QVR", "QES", \
                     "QVR Pro Client"]

            # 使用 key 函數按照順序排序
            try:
                products = sorted(products, key=lambda x: order.index(x))
            except Exception:
                pass

            sa_title = ''
            for product in products:
                if len(sa_title)>0:
                    sa_title += ', '
                sa_title += product
        elif 'summary' in self.json_obj['raw']:
            sa_title = extract_sa_title(self.json_obj['raw']['summary'])

        if len(sa_title)>0:
            return sa_title
        return None

    def retrieve_qsa_product_in_bugs(self, issuekey, qsa):
        ### 確定 qsa 中，有 releaseissue 階層
        if 'releaseissue' not in qsa:
            qsa['releaseissue'] = {}
        releaseissue_obj = qsa['releaseissue']

        ### 指定 releaseissue 階層的參數
        xbugs = self.json_obj['bugs']

        sa_title = self.extract_sa_title()
        if not sa_title:
            sa_title = ''
        releaseissue_obj['sa_title'] = sa_title
        print('--- sa_title = ' + sa_title)

        if 'affected_products' not in releaseissue_obj:
            releaseissue_obj['affected_products'] = []
        if 'fixing_products' not in releaseissue_obj:
            releaseissue_obj['fixing_products'] = []

        for bug in xbugs:
            the_product, the_version_begin = raw.get_product_name(bug['summary'])
            if the_product=='QNE':
                continue
            if bug['affected']=='No':
                version_data = {}
                version_data['platform'] = ''
                version_data['version_affected'] = 'x'
                version_data['version_value'] = ''
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
            else:
                releaseissue_obj['affected_products'] = raw.make_product_list(bug['summary'], releaseissue_obj['affected_products'])
                if bug['done']=='No':
                    releaseissue_obj['fixing_products'] = raw.make_product_list(bug['summary'], releaseissue_obj['fixing_products'])
        # 定義順序列表
        order = ["QTS", "QuTS hero", "QuTScloud", "QNE", "QVP (QVR Pro appliances)", "QVR", "QES", \
                 "QVR Pro Client"]

        # 使用 key 函數按照順序排序
        try:
            releaseissue_obj['affected_products'] = sorted(releaseissue_obj['affected_products'], key=lambda x: order.index(x))
            print('affected_products >>>> '+str(releaseissue_obj['affected_products']))
        except Exception:
            pass
        
        try:
            releaseissue_obj['fixing_products'] = sorted(releaseissue_obj['fixing_products'], key=lambda x: order.index(x))
            print('fixing_products   >>>> '+str(releaseissue_obj['fixing_products']))
        except Exception:
            pass

        ### 將 qsa 位址回傳
        return qsa


    def retrieve_qsa_product_in_releases(self, issuekey, qsa):
        ### 確定 qsa 中，有 releaseissue 階層
        if 'releaseissue' not in qsa:
            qsa['releaseissue'] = {}
        releaseissue_obj = qsa['releaseissue']

        ### 指定 releaseissue 階層的參數
        xreleaseproc = self.json_obj['releases']

        for rec_data in xreleaseproc:
            if rec_data['done']=='Yes':
                if rec_data['product']=='ADRA Global':
                    continue
                the_product = rec_data['product']
                the_platform = rec_data['platform']
                the_version = rec_data['version_n_build']
                the_version_begin = rec_data['version_begin']

                version_data = {}
                version_data['platform'] = the_platform
                version_data['version_affected'] = '<'
                version_data['version_value'] = the_version
                version_data['version_begin'] = the_version_begin

                # 從 map 轉成 array
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
                        b_updated = True # 已存在，更新
                if not b_updated:
                     # 新增一筆
                    releaseissue_obj['product_data'].append({
                            'product_name': the_product,
                            'version': { 'version_data': [version_data] }
                        })

        ### 將 qsa 位址回傳
        return qsa
    
    def retrieve_rn_in_releases(self, issuekey, rn):
        '''
        rn 
        {
            'releaseissue': # releaseissue_obj
            {
                rnkey: # the_product + ' ' + [the_platform + ' '] + the_version
                {
                    'cveid': [],
                    'jirakey': [],
                },
            }
        }
        '''
        ### 確定 rn 中，有 releaseissue 階層
        if 'releaseissue' not in rn:
            rn['releaseissue'] = {}
        releaseissue_obj = rn['releaseissue']

        ### 指定 releaseissue 階層的參數
        xreleaseproc = self.json_obj['releases']

        for rec_data in xreleaseproc:
            if rec_data['done']=='Yes' and 'cveid' in self.json_obj['raw']:
                the_product = rec_data['product']
                the_platform = rec_data['platform']
                the_version = rec_data['version_n_build']
                the_jirakey = rec_data['key']
                the_cveid = self.json_obj['raw']['cveid']

                # key =  the_product + ' ' + [the_platform + ' '] + the_version
                if the_product is None or len(the_product)==0:
                    continue
                rnkey = the_product + ' '
                if the_platform and len(the_platform)>0:
                    rnkey += the_platform + ' '
                rnkey += the_version
                if rnkey not in releaseissue_obj:
                    releaseissue_obj[rnkey] = {}
                the_row = releaseissue_obj[rnkey]
                if 'cveid' not in the_row:
                    the_row['cveid'] = []
                if the_cveid not in the_row['cveid'] and len(the_cveid)>0:
                    the_row['cveid'].append(the_cveid)
                if 'jirakey' not in the_row:
                    the_row['jirakey'] = []
                if the_jirakey not in the_row['jirakey'] and len(the_jirakey)>0:
                    the_row['jirakey'].append(the_jirakey)

        ### 將 rn 位址回傳
        return rn
    
    def dump_raw(self):
        print('ID            創建        修復            驗證            測試        上架')
        ### 指定 raw 階層的參數
        raw = self.json_obj['raw']
        key = raw['key']
        fixing = '          '
        if 'fixing' in raw and raw['fixing'] != 'N/A':
            fixing = raw['fixing']
        resolved = '          '
        if 'resolved' in raw and raw['resolved'] != 'N/A':
            resolved = raw['resolved']
        verified = '          '
        if 'verified' in raw and raw['verified'] != 'N/A':
            verified = raw['verified']
        labtest = '          '
        if 'labtest' in raw and raw['labtest'] != 'N/A':
            labtest = raw['labtest']
        release = '          '
        if 'release' in raw and raw['release'] != 'N/A':
            release = raw['release']
        resolved_duration = '   '
        if 'resolved_duration' in raw:
            resolved_duration = raw['resolved_duration']
            if resolved_duration == 'N/A':
                resolved_duration = 0
            resolved_duration = f"{int(resolved_duration):03d}"
        verified_duration = '   '
        if 'verified_duration' in raw:
            verified_duration = raw['verified_duration']
            if verified_duration == 'N/A':
                verified_duration = 0
            verified_duration = f"{int(verified_duration):03d}"
        release_duration = '   '
        if 'release_duration' in raw:
            release_duration = raw['release_duration']
            if release_duration == 'N/A':
                release_duration = 0
            release_duration = f"{int(release_duration):03d}"
        print('{key} {fixing}  {resolved} {resolved_duration}  {verified} {verified_duration}  {labtest}  {release} {release_duration}'.format(
            key=key,
            fixing=fixing,
            resolved=resolved,
            resolved_duration=resolved_duration,
            verified=verified,
            verified_duration=verified_duration,
            labtest=labtest,
            release=release,
            release_duration=release_duration))
    
    def dump_bugs(self):
        print('ID            創建        修復            驗證            測試        上架')
        ### 指定 bugs 階層的參數
        xbugs = self.json_obj['bugs']
        for bug in xbugs:
            key = bug['key']
            created = '          '
            if 'created' in bug:
                created = bug['created']
            resolved = '          '
            if 'resolved' in bug:
                resolved = bug['resolved']
            verified = '          '
            if 'verified' in bug:
                verified = bug['verified']
            labtest = '          '
            if 'labtest' in bug:
                labtest = bug['labtest']
            released = '          '
            if 'released' in bug:
                released = bug['released']
            resolved_days = '   '
            if 'resolved_days' in bug:
                resolved_days = bug['resolved_days']
                if resolved_days == 'N/A':
                    resolved_days = 0
                resolved_days = f"{int(resolved_days):03d}"
            verified_days = '   '
            if 'verified_days' in bug:
                verified_days = bug['verified_days']
                if verified_days == 'N/A':
                    verified_days = 0
                verified_days = f"{int(verified_days):03d}"
            duration = '   '
            if 'duration' in bug:
                duration = bug['duration']
                if duration == 'N/A':
                    duration = 0
                duration = f"{int(duration):03d}"

            print('{key} {created}  {resolved} {resolved_days}  {verified} {verified_days}  {labtest}  {released} {duration}'.format(
                key=key,
                created=created,
                resolved=resolved,
                resolved_days=resolved_days,
                verified=verified,
                verified_days=verified_days,
                labtest=labtest,
                released=released,
                duration=duration))
