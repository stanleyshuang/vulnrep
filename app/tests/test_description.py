# -*- coding: utf-8 -*-
#
# Author:   Stanley Huang
# Project:  vulnrep ver. 1.0
# Date:     2021/07/02
#
import unittest
from pkg.qjira.description import extract_severity_level
from pkg.qjira.description import extract_cveid
from pkg.qjira.description import extract_cweid
from pkg.qjira.description import extract_sa_title
from pkg.qjira.description import extract_pf_pt_ver
from pkg.qjira.description import severity_level_2_cvssv3_score

class ExtractSeveritylevelTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass
    
    def test_extract_severity_level_10(self):
        self.assertTrue('[V3]'==extract_severity_level('[INTSI000-1023][Web][Security][Medium][V3] CSRF leads to change account settings of a victim (Mark Ella)'))

class ExtractCveidTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass
    
    def test_extract_cveid_10(self):
        self.assertTrue(None==extract_cveid('[INTSI000-1023][Web][Security][Medium][V3] CSRF leads to change account settings of a victim (Mark Ella)'))

    def test_extract_cveid_20(self):
        self.assertTrue('CVE-2021-28815'==extract_cveid('[QPKG][Security][Medium][V3] Exposure of Sensitive Information in CloudLink - CVE-2021-28815 (xxyantixx)'))

class ExtractCweidTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass
    
    def test_extract_cweid_10(self):
        self.assertTrue('CWE-798'==extract_cweid('CWE-798 Use of Hard-coded Credentials'))

    def test_extract_cweid_20(self):
        self.assertTrue(None==extract_cweid('Hello World'))

class ExtractSaTitleTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass
    
    def test_extract_sa_title_10(self):
        self.assertTrue('CSRF leads to change account settings of a victim'==extract_sa_title('[INTSI000-1023][Web][Security][Medium][V3] CSRF leads to change account settings of a victim (Mark Ella)'))

    def test_extract_sa_title_20(self):
        self.assertTrue('Exposure of Sensitive Information in CloudLink'==extract_sa_title('[QPKG][Security][Medium][V3] Exposure of Sensitive Information in CloudLink - CVE-2021-28815 (xxyantixx)'))

    def test_extract_sa_title_30(self):
        self.assertTrue('WebView loads files from external storage'==extract_sa_title('[KoiTalk Android][Security][Low][V2] WebView loads files from external storage'))

    def test_extract_sa_title_40(self):
        self.assertTrue('Janus vulnerability'==extract_sa_title('[Qcontactz Android][Security] Janus vulnerability'))
        
    def test_extract_sa_title_50(self):
        self.assertTrue('Attribute hasFragileUserData not set'==extract_sa_title('Attribute hasFragileUserData not set'))
        
    def test_extract_sa_title_60(self):
        self.assertTrue('Roon Server的QNAP设备中发现两个0Day漏洞'==extract_sa_title('[QPKG][3rdParty][Security][Critical][V5] Roon Server的QNAP设备中发现两个0Day漏洞'))
        
    def test_extract_sa_title_70(self):
        self.assertTrue('ADB Backup allowed'==extract_sa_title('[KoiTalk][Android][Security]INTSI000-1005 ADB Backup allowed'))
        
    def test_extract_sa_title_80(self):
        self.assertTrue('Exposure of Sensitive Information in CloudLink'==extract_sa_title('\u00a0INTSI000-732[QPKG][Security][Medium][V3] Exposure of Sensitive Information in CloudLink -\u00a0CVE-2021-28815 (xxyantixx)'))
        
    def test_extract_sa_title_90(self):
        self.assertTrue('Use of Hard-coded Credentials'==extract_sa_title('[QSS][Security][High][V4] Use of Hard-coded Credentials - CVE-2021-28813 (Sergey)'))

class ExtractPfPtVerTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass
    
    def test_extract_pf_pt_ver_10(self):
        self.assertTrue(['QTS 4.5.3', 'myQNAPcloud Link', '2.2.21']==extract_pf_pt_ver('[CVE-2021-28815][FIX]: [QTS 4.5.3] [myQNAPcloud Link] [2.2.21]'))

    def test_extract_pf_pt_ver_20(self):
        self.assertTrue(['QuTS hero h4.5.2', 'myQNAPcloud Link', '2.2.21']==extract_pf_pt_ver('[CVE-2021-28815][FIX]: [QuTS hero h4.5.2] [myQNAPcloud Link] [2.2.21]'))

    def test_extract_pf_pt_ver_30(self):
        self.assertTrue(['QuTScloud c4.5.4', 'myQNAPcloud Link', '2.2.21']==extract_pf_pt_ver('[CVE-2021-28815][FIX]: [QuTScloud c4.5.4] [myQNAPcloud Link] [2.2.21]'))

class SeverityLevel2Cvssv3ScoreTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass
    
    def test_severity_level_2_cvssv3_score_10(self):
        self.assertTrue('0.0', '1.9'==severity_level_2_cvssv3_score('[V1]'))
    
    def test_severity_level_2_cvssv3_score_20(self):
        self.assertTrue('2.0', '3.9'==severity_level_2_cvssv3_score('[V2]'))
    
    def test_severity_level_2_cvssv3_score_30(self):
        self.assertTrue('4.0', '6.9'==severity_level_2_cvssv3_score('[V3]'))
    
    def test_severity_level_2_cvssv3_score_40(self):
        self.assertTrue('7.0', '8.9'==severity_level_2_cvssv3_score('[V4]'))
    
    def test_severity_level_2_cvssv3_score_50(self):
        self.assertTrue('9.0', '10.0'==severity_level_2_cvssv3_score('[V5]'))

