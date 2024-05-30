# -*- coding: utf-8 -*-
#
# Author:   Stanley Huang
# Project:  vulnrep ver. 1.0
# Date:     2021/07/02
#
import unittest
from pkg._qjira.description import extract_str_in_link
from pkg._qjira.description import extract_severity_level
from pkg._qjira.description import extract_model
from pkg._qjira.description import extract_cveid
from pkg._qjira.description import extract_cweid
from pkg._qjira.description import extract_capecid
from pkg._qjira.description import extract_quality_score
from pkg._qjira.description import extract_cvss_score
from pkg._qjira.description import extract_cvssv3_attr
from pkg._qjira.description import extract_cvssv4_attr
from pkg._qjira.description import extract_sa_title
from pkg._qjira.description import extract_pf_pt_ver
from pkg._qjira.description import sync_summary_content
from pkg._qjira.description import severity_level_2_cvssv3_score
from pkg._qjira.description import parse_fw_delivery_process
from pkg._qjira.description import parse_fw_release_process
from pkg._qjira.description import parse_app_release_process
from pkg._qjira.description import parse_store_publish_process


class ExtractStrInLinkTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_extract_str_in_link_10(self):
        b_need_update, name, link, others = extract_str_in_link(
            "[https://qnap.lightning.force.com/lightning/r/Case/5002s00000DDUgjAAH/view]"
        )
        self.assertTrue(
            True == b_need_update
            and "" == name
            and "https://qnap.lightning.force.com/lightning/r/Case/5002s00000DDUgjAAH/view"
            == link
            and "" == others
        )

    def test_extract_str_in_link_20(self):
        b_need_update, name, link, others = extract_str_in_link(
            "[http://10.26.34.83:8080/cgi-bin/application/appRequest.cgi?sid=qpje5sy8&subfunc=hdstation|http://10.26.34.83:8080/cgi-bin/application/appRequest.cgi?sid=qpje5sy8&subfunc=hdstation%27]"
        )
        self.assertTrue(
            False == b_need_update
            and "" == name
            and "http://10.26.34.83:8080/cgi-bin/application/appRequest.cgi?sid=qpje5sy8&subfunc=hdstation%27"
            == link
            and "" == others
        )

    def test_extract_str_in_link_30(self):
        description = (
            "h3. *\{color:#de350b\}1. 依據公司政策 所有 V3 (含) 等級以上的資安 bug 單 RD 在正式進 code 前  除了各單位內部的 code review 機制 需要額外指派資安 reviewer 協助做 security code review (方法可以參考此文件 [https://ieinet.sharepoint.com/:p:/r/sites/msteams_7625dd/Shared%20Documents/BSIMM/%E9%A0%90%E9%98%B2%E5%B7%A5%E4%BD%9C/CodeReview/CodeReview%E6%B5%81%E7%A8%8B%E8%88%87%E7%A8%BD%E6%A0%B8.pptx?d=w86909161a88d4f6380595bfc4a5aa066&csf=1&web=1&e=3ybLWv])\{color\}*\n"
            "h3. \{*\}\{color:#de350b\}2. 請先完成單位內部的 code review 再指派給資安 reviewer 進行 security code review\{color\}\{*\}\n"
            "h3. *\{color:#de350b\}3. 如需參與 QTS code review 審查會議 請先完成 security code review\{color\}*\n"
            "h3. *\{color:#de350b\}4. 此資安 bug 單的資安 reviewer 為軟體架構部 Kevin Liao\{color\}*\n"
            "[Q-202306-20790|https://qnap.lightning.force.com/lightning/r/Case/5002s00000YhaXcAAJ/view]\n"
            "[zero one] [bugfinder0@outlook.com]\n"
            "[sf-subject] [SF:Q-202306-20790] A report of three vulnerabilities in QTS\n"
            "Dear QNAP Security Team:\n\n"
            "We found six new vulnerabilities in QTS 5.0.1.2376, which allow user to perform DoS attack or get a root shell.\n"
            "Detailed reports, PoCs and videos about these six vulnerabilities are in the attachment. [https://1drv.ms/u/s!AsvXf7uhShA0gRt80TsGoxw-i2yR]\n"
            "Looking forward to your reply.\n"
            "bugfinder\n"
        )
        b_need_update, name, link, others = extract_str_in_link(description)
        self.assertTrue(
            False == b_need_update
            and "Q-202306-20790" == name
            and "https://qnap.lightning.force.com/lightning/r/Case/5002s00000YhaXcAAJ/view"
            == link
        )


class ExtractModelTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_extract_model_10(self):
        cat, product, ver_begin = extract_model(
            "[INTSI000-1025][Web][Security][Medium][V3] User Account hacking -> https://license2.qnap.com (Mark Ella)"
        )
        self.assertTrue(
            "qnap website" == cat and "Web" == product and "n/a" == ver_begin
        )

    def test_extract_model_20(self):
        cat, product, ver_begin = extract_model(
            "[QNAP Cloud Service][Security][Medium][V3] Exposure of Sensitive Information in doc.alpha.qmiix.com - CVE-2017-5487 (Prajit Sindhkar)"
        )
        self.assertTrue(
            "qnap cloud service" == cat
            and "QNAP Cloud Service" == product
            and "n/a" == ver_begin
        )

    def test_extract_model_30(self):
        cat, product, ver_begin = extract_model(
            "[Q-202204-00401][INTSI000-3257][Windows Utility:QENC Decrypter Windows][Security][Medium][V3] Out-of-bounds Write in QENCDecrypter (RunZi Zhao) - CVE-2022-27590"
        )
        self.assertTrue(
            "utility" == cat
            and "QENC Decrypter Windows" == product
            and "x" == ver_begin
        )

    def test_extract_model_40(self):
        cat, product, ver_begin = extract_model(
            "[Android:Qmiix][Security][Medium][V3] Cleartext Storage of Sensitive Information"
        )
        self.assertTrue("android" == cat and "Qmiix" == product and "x" == ver_begin)


class ExtractSeveritylevelTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_extract_severity_level_10(self):
        self.assertTrue(
            "[V3]"
            == extract_severity_level(
                "[INTSI000-1023][Web][Security][Medium][V3] CSRF leads to change account settings of a victim (Mark Ella)"
            )
        )

    def test_extract_severity_level_20(self):
        self.assertTrue(
            "[V3]"
            == extract_severity_level(
                "[QNAP Cloud Service][Security][Medium][V3] Mass Account Takeovers - Credential Stuffing / Sensitive InformationLeaks leads to ATO"
            )
        )


class ExtractCveidTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_extract_cveid_10(self):
        self.assertTrue(
            None
            == extract_cveid(
                "[INTSI000-1023][Web][Security][Medium][V3] CSRF leads to change account settings of a victim (Mark Ella)"
            )
        )

    def test_extract_cveid_20(self):
        self.assertTrue(
            "CVE-2021-28815"
            == "|".join(
                extract_cveid(
                    "[QPKG][Security][Medium][V3] Exposure of Sensitive Information in CloudLink - CVE-2021-28815 (xxyantixx)"
                )
            )
        )

    def test_extract_cveid_30(self):
        self.assertTrue(
            "CVE-2021-28815|CVE-2021-28816"
            == "|".join(
                extract_cveid(
                    "[QPKG][Security][Medium][V3] Exposure of Sensitive Information in CloudLink - CVE-2021-28815|CVE-2021-28816 (xxyantixx)"
                )
            )
        )


class ExtractCweidTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_extract_cweid_10(self):
        cweids = extract_cweid("CWE-798 Use of Hard-coded Credentials")
        self.assertTrue(["CWE-798"] == cweids)

    def test_extract_cweid_20(self):
        cweids = extract_cweid("Hello World")
        self.assertTrue([] == cweids)

    def test_extract_cweid_30(self):
        cweids = extract_cweid("CWE-798,CWE-123, CWE-400")
        self.assertTrue(["CWE-123", "CWE-400", "CWE-798"] == cweids)


class ExtractCapecidTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_extract_capecid_10(self):
        capecids = extract_capecid("CAPEC-36: Using Unpublished Interfaces")
        self.assertTrue(["CAPEC-36"] == capecids)

    def test_extract_capecid_20(self):
        capecids = extract_capecid("Hello MITRE")
        self.assertTrue([] == capecids)

    def test_extract_capecid_30(self):
        capecids = extract_capecid(
            "CAPEC-36: Using Unpublished Interfaces, CAPEC-123: Buffer Manipulation"
        )
        self.assertTrue(["CAPEC-123", "CAPEC-36"] == capecids)


class ExtractQualityScoreTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_extract_quality_score_10(self):
        self.assertTrue(
            5 == extract_quality_score("description", "Description (描述的品質)： 5")
        )

    def test_extract_quality_score_20(self):
        self.assertTrue(None == extract_quality_score("poc", "Hello MITRE"))

    def test_extract_quality_score_30(self):
        self.assertTrue(3 == extract_quality_score("PoC", "POC (概念性證明的品質)：3"))

    def test_extract_quality_score_40(self):
        self.assertTrue(1 == extract_quality_score("SUGGESTION", "Suggestion 1"))

    def test_extract_quality_score_50(self):
        self.assertTrue(
            4 == extract_quality_score("description", "Description score: 4")
        )

    def test_extract_quality_score_60(self):
        self.assertTrue(4 == extract_quality_score("poc", "POC score: 4"))

    def test_extract_quality_score_70(self):
        self.assertTrue(2 == extract_quality_score("suggestion", "Suggestion score: 2"))


class ExtractCvssv3ScoreTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_extract_cvss_score_10(self):
        vec, score, b_40 = extract_cvss_score(
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N (7.6)"
        )
        self.assertTrue(
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N" == vec and "7.6" == score and not b_40
        )

    def test_extract_cvss_score_101(self):
        vec, score, b_40 = extract_cvss_score(
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N-7.6"
        )
        self.assertTrue(
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N" == vec and "7.6" == score and not b_40
        )

    def test_extract_cvss_score_11(self):
        vec, score, b_40 = extract_cvss_score(
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N (2.4)"
        )
        self.assertTrue(
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N" == vec and "2.4" == score and b_40
        )

    def test_extract_cvss_score_111(self):
        vec, score, b_40 = extract_cvss_score(
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N-2.4"
        )
        self.assertTrue(
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N" == vec and "2.4" == score and b_40
        )

    def test_extract_cvss_score_12(self):
        vec, score, b_40 = extract_cvss_score(
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:P (0.9)"
        )
        self.assertTrue(
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:P" == vec and "0.9" == score and b_40
        )

    def test_extract_cvss_score_121(self):
        vec, score, b_40 = extract_cvss_score(
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:P-0.9"
        )
        self.assertTrue(
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:P" == vec and "0.9" == score and b_40
        )

    def test_extract_cvss_score_20(self):
        vec, score, b_40 = extract_cvss_score("Hello World")
        self.assertTrue(None == vec and None == score) and None == b_40

    def test_extract_cvss_score_30(self):
        vec, score, b_40 = extract_cvss_score(
            "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
        )
        self.assertTrue(
            "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" == vec and None == score and not b_40
        )

    def test_extract_cvss_score_31(self):
        vec, score, b_40 = extract_cvss_score(
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
        )
        self.assertTrue(
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N" == vec and None == score and b_40
        )

    def test_extract_cvss_score_32(self):
        vec, score, b_40 = extract_cvss_score(
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:P"
        )
        self.assertTrue(
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:P" == vec and None == score and b_40
        )

    def test_extract_cvss_score_40(self):
        vec, score, b_40 = extract_cvss_score(
            "CVSSv3 score: 4.3"
        )
        self.assertTrue(
            None == vec and "4.3" == score and not b_40
        )

    def test_extract_cvss_score_41(self):
        vec, score, b_40 = extract_cvss_score(
            "CVSSv4 score: 5.3"
        )
        self.assertTrue(
            None == vec and "5.3" == score and b_40
        )

    def test_extract_cvss_score_42(self):
        vec, score, b_40 = extract_cvss_score(
            "CVSSv4 base + threat score: 2.1"
        )
        self.assertTrue(
            None == vec and "2.1" == score and b_40
        )


class ExtractCvssv3AttrTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_extract_cvssv3_attr_10(self):
        av, ac, pr, ui, s, c, i, a = extract_cvssv3_attr(
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N (7.6)"
        )
        self.assertTrue(
            "N" == av
            and "L" == ac
            and "L" == pr
            and "R" == ui
            and "C" == s
            and "H" == c
            and "L" == i
            and "N" == a
        )

    def test_extract_cvssv3_attr_20(self):
        av, ac, pr, ui, s, c, i, a = extract_cvssv3_attr("Hello World")
        self.assertTrue(
            None == av
            and None == ac
            and None == pr
            and None == ui
            and None == s
            and None == c
            and None == i
            and None == a
        )


class ExtractCvssv4AttrTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_extract_cvssv4_attr_10(self):
        av, ac, at, pr, ui, vc, vi, va, sc, si, sa, e = extract_cvssv4_attr(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N-5.3"
        )
        self.assertTrue(
            "N" == av
            and "L" == ac
            and "N" == at
            and "L" == pr
            and "N" == ui
            and "N" == vc
            and "N" == vi
            and "L" == va
            and "N" == sc
            and "N" == si
            and "N" == sa
            and None == e
        )

    def test_extract_cvssv4_attr_20(self):
        av, ac, at, pr, ui, vc, vi, va, sc, si, sa, e = extract_cvssv4_attr(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N/E:P-2.1"
        )
        self.assertTrue(
            "N" == av
            and "L" == ac
            and "N" == at
            and "L" == pr
            and "N" == ui
            and "N" == vc
            and "N" == vi
            and "L" == va
            and "N" == sc
            and "N" == si
            and "N" == sa
            and "P" == e
        )


class ExtractSaTitleTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_extract_sa_title_10(self):
        self.assertTrue(
            "CSRF leads to change account settings of a victim"
            == extract_sa_title(
                "[INTSI000-1023][Web][Security][Medium][V3] CSRF leads to change account settings of a victim (Mark Ella)"
            )
        )

    def test_extract_sa_title_20(self):
        self.assertTrue(
            "Exposure of Sensitive Information in CloudLink"
            == extract_sa_title(
                "[QPKG][Security][Medium][V3] Exposure of Sensitive Information in CloudLink - CVE-2021-28815 (xxyantixx)"
            )
        )

    def test_extract_sa_title_30(self):
        self.assertTrue(
            "WebView loads files from external storage"
            == extract_sa_title(
                "[KoiTalk Android][Security][Low][V2] WebView loads files from external storage"
            )
        )

    def test_extract_sa_title_40(self):
        self.assertTrue(
            "Janus vulnerability"
            == extract_sa_title("[Qcontactz Android][Security] Janus vulnerability")
        )

    def test_extract_sa_title_50(self):
        self.assertTrue(
            "Attribute hasFragileUserData not set"
            == extract_sa_title("Attribute hasFragileUserData not set")
        )

    def test_extract_sa_title_60(self):
        self.assertTrue(
            "Roon Server的QNAP设备中发现两个0Day漏洞"
            == extract_sa_title(
                "[QPKG][3rdParty][Security][Critical][V5] Roon Server的QNAP设备中发现两个0Day漏洞"
            )
        )

    def test_extract_sa_title_70(self):
        self.assertTrue(
            "ADB Backup allowed"
            == extract_sa_title(
                "[KoiTalk][Android][Security]INTSI000-1005 ADB Backup allowed"
            )
        )

    def test_extract_sa_title_80(self):
        self.assertTrue(
            "Exposure of Sensitive Information in CloudLink"
            == extract_sa_title(
                "\u00a0INTSI000-732[QPKG][Security][Medium][V3] Exposure of Sensitive Information in CloudLink -\u00a0CVE-2021-28815 (xxyantixx)"
            )
        )

    def test_extract_sa_title_90(self):
        self.assertTrue(
            "Use of Hard-coded Credentials"
            == extract_sa_title(
                "[QSS][Security][High][V4] Use of Hard-coded Credentials - CVE-2021-28813 (Sergey)"
            )
        )

    def test_extract_sa_title_100(self):
        self.assertTrue(
            "Stack_overflow_in_CreateProcessAsWhom_exe_of_QENCDecrypter"
            == extract_sa_title(
                "[QENC Decrypter Windows][Security][Medium][V3] Stack_overflow_in_CreateProcessAsWhom_exe_of_QENCDecrypter"
            )
        )

    def test_extract_sa_title_110(self):
        sa_title = extract_sa_title(
            "[SF:Q-202303-57779][main][QTS] Multiple command injection vulnerabilities (Jinwei Dong) - CVE-2023-23367"
        )
        self.assertTrue("Multiple command injection vulnerabilities" == sa_title)

    def test_extract_sa_title_120(self):
        sa_title = extract_sa_title(
            "[Android:QuMagie][Security][Medium][V3] jackson-databind - (3rd-party) CVE-2022-42004 | CVE-2022-42003 | CVE-2020-36518 | CVE-2021-46877"
        )
        self.assertTrue("jackson-databind" == sa_title)


class ExtractPfPtVerTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_extract_pf_pt_ver_10(self):
        self.assertTrue(
            ["QTS 4.5.3", "myQNAPcloud Link", "2.2.21"]
            == extract_pf_pt_ver(
                "[CVE-2021-28815][FIX]: [QTS 4.5.3] [myQNAPcloud Link] [2.2.21]"
            )
        )

    def test_extract_pf_pt_ver_20(self):
        self.assertTrue(
            ["QuTS hero h4.5.2", "myQNAPcloud Link", "2.2.21"]
            == extract_pf_pt_ver(
                "[CVE-2021-28815][FIX]: [QuTS hero h4.5.2] [myQNAPcloud Link] [2.2.21]"
            )
        )

    def test_extract_pf_pt_ver_30(self):
        self.assertTrue(
            ["QuTScloud c4.5.4", "myQNAPcloud Link", "2.2.21"]
            == extract_pf_pt_ver(
                "[CVE-2021-28815][FIX]: [QuTScloud c4.5.4] [myQNAPcloud Link] [2.2.21]"
            )
        )


class SyncSummaryContentTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_sync_summary_content_10(self):
        self.assertTrue(
            "[Qmiix Android][Security][Medium][V3] Secret information stored in the application"
            == sync_summary_content(
                "[Qmiix Android][Security][Medium][V3] Secret information stored in the application",
                "[Qmiix Android][Security][Medium][V3] Secret information stored in the application",
            )
        )

    def test_sync_summary_content_20(self):
        self.assertTrue(
            "[QTS 5.0.0][Security][Medium][V3] Secret information stored in the application"
            == sync_summary_content(
                "[QTS][Security][Medium][V3] Secret information stored in the application",
                "[QTS 5.0.0][Security][Medium][V3] Task Hijack",
            )
        )

    def test_sync_summary_content_30(self):
        self.assertTrue(
            "[QTS 5.0.0] Secret information stored in the application"
            == sync_summary_content(
                "Secret information stored in the application",
                "[QTS 5.0.0][Security][Medium][V3] Task Hijack",
            )
        )

    def test_sync_summary_content_40(self):
        self.assertTrue(
            "[QTS 5.0.0][QTS][Security][Medium][V3] Secret information stored in the application"
            == sync_summary_content(
                "[QTS][Security][Medium][V3] Secret information stored in the application",
                "[QTS 5.0.0][QTS][Security][Medium][V3] Task Hijack",
            )
        )


class SeverityLevel2Cvssv3ScoreTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_severity_level_2_cvssv3_score_10(self):
        low, high = severity_level_2_cvssv3_score("[V1]")
        self.assertTrue("0.0" == low and "1.9" == high)

    def test_severity_level_2_cvssv3_score_20(self):
        low, high = severity_level_2_cvssv3_score("[V2]")
        self.assertTrue("2.0" == low and "3.9" == high)

    def test_severity_level_2_cvssv3_score_30(self):
        low, high = severity_level_2_cvssv3_score("[V3]")
        self.assertTrue("4.0" == low and "6.9" == high)

    def test_severity_level_2_cvssv3_score_40(self):
        low, high = severity_level_2_cvssv3_score("[V4]")
        self.assertTrue("7.0" == low and "8.9" == high)

    def test_severity_level_2_cvssv3_score_50(self):
        low, high = severity_level_2_cvssv3_score("[V5]")
        self.assertTrue("9.0" == low and "10.0" == high)


class ParseFwDeliveryProcessQtsBuildTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_parse_fw_delivery_process_10(self):
        product, platform, ver_n_bld, ver_begin = parse_fw_delivery_process(
            "QSSM2116-341", "QSW-M2116P-2T2S", "v1.0.6_S210713_26146"
        )
        self.assertTrue(
            "QSW-M2116P-2T2S" == product
            and "" == platform
            and "1.0.6 build 210713" == ver_n_bld
            and "1.0.x" == ver_begin
        )

    def test_parse_fw_delivery_process_20(self):
        product, platform, ver_n_bld, ver_begin = parse_fw_delivery_process(
            "", None, None
        )
        self.assertTrue(
            "" == product and "" == platform and "" == ver_n_bld and "" == ver_begin
        )

    def test_parse_fw_delivery_process_30(self):
        product, platform, ver_n_bld, ver_begin = parse_fw_delivery_process(
            "QTS00000-9417", "", "QTS 5.0.0.1716 build 20210701"
        )
        self.assertTrue(
            "QTS" == product
            and "" == platform
            and "5.0.0.1716 build 20210701" == ver_n_bld
            and "5.0.x" == ver_begin
        )

    def test_parse_fw_delivery_process_40(self):
        product, platform, ver_n_bld, ver_begin = parse_fw_delivery_process(
            "QTS00000-9417", "", "4.3.3.1693 #20210624"
        )
        self.assertTrue(
            "QTS" == product
            and "" == platform
            and "4.3.3.1693 build 20210624" == ver_n_bld
            and "4.3.x" == ver_begin
        )

    def test_parse_fw_delivery_process_41(self):
        product, platform, ver_n_bld, ver_begin = parse_fw_delivery_process(
            "QTS00000-12011",
            "TS-421U, TS-421, TS-420U, TS-420-D, TS-420, TS-419U II, TS-419U+, TS-419U, TS-419P II, TS-419P+, TS-419P, TS-412U, TS-412, TS-221, TS-220, TS-219P II, TS-219P+, TS-219P, TS-219, TS-212P, TS-212-E, TS-212, HS-210, HS-210-D, HS-210-Onkyo, TS-121, TS-120, TS-119P II, TS-119P+, TS-112, TS-112P, TAS-168, TAS-268",
            "QTS 4.3.3.1945 build 20220303",
        )
        self.assertTrue(
            "QTS" == product
            and "" == platform
            and "4.3.3.1945 build 20220303" == ver_n_bld
            and "4.3.x" == ver_begin
        )

    def test_parse_fw_delivery_process_42(self):
        product, platform, ver_n_bld, ver_begin = parse_fw_delivery_process(
            "QTS00000-11979",
            "TS-269, TS-469, TS-469U, TS-569, TS-669, TS-869, TS-869U, TS-1269U",
            "4.3.4.1976 #20220303",
        )
        self.assertTrue(
            "QTS" == product
            and "" == platform
            and "4.3.4.1976 build 20220303" == ver_n_bld
            and "4.3.x" == ver_begin
        )

    def test_parse_fw_delivery_process_43(self):
        product, platform, ver_n_bld, ver_begin = parse_fw_delivery_process(
            "QTS00000-12256", "...", "5.0.0.1986 build 20220324"
        )
        self.assertTrue(
            "QTS" == product
            and "" == platform
            and "5.0.0.1986 build 20220324" == ver_n_bld
            and "5.0.x" == ver_begin
        )

    def test_parse_fw_delivery_process_44(self):
        product, platform, ver_n_bld, ver_begin = parse_fw_delivery_process(
            "QTS00000-12013", "...", "QTS 4.2.6 build 20220304"
        )
        self.assertTrue(
            "QTS" == product
            and "" == platform
            and "4.2.6 build 20220304" == ver_n_bld
            and "4.2.x" == ver_begin
        )

    def test_parse_fw_delivery_process_45(self):
        product, platform, ver_n_bld, ver_begin = parse_fw_delivery_process(
            "QTS00000-13634",
            "...",
            "5.0.1.2131",
            filelink="\\\\172.17.21.5\\pub\\daily_build\\QTS_5.0.1\\2131",
        )
        self.assertTrue(
            "QTS" == product
            and "" == platform
            and "5.0.1.2131" == ver_n_bld
            and "5.0.x" == ver_begin
        )

    def test_parse_fw_delivery_process_50(self):
        product, platform, ver_n_bld, ver_begin = parse_fw_delivery_process(
            "CLDVCLD0-2062", "QuTScloud", "c4.5.6.1751"
        )
        self.assertTrue(
            "QuTScloud" == product
            and "" == platform
            and "c4.5.6.1751" == ver_n_bld
            and "c4.5.x" == ver_begin
        )

    def test_parse_fw_delivery_process_60(self):
        product, platform, ver_n_bld, ver_begin = parse_fw_delivery_process(
            "HEROMANP-1590",
            "TS-h3088XU\nTVS-h1288X/TVS-h1688X",
            "20210825-h4.5.4.1771.img",
        )
        self.assertTrue(
            "QuTS hero" == product
            and "" == platform
            and "h4.5.4.1771 build 20210825" == ver_n_bld
            and "h4.5.x" == ver_begin
        )

    def test_parse_fw_delivery_process_61(self):
        product, platform, ver_n_bld, ver_begin = parse_fw_delivery_process(
            "HEROMANP-813",
            "TS-h2490FU\nTVS-h1288X/TVS-h1688X\nTS-h686/TS-h886\nTS-h1886XU\nTS-h1283XU/TS-h1683XU/TS-h2483XU\nTNS-h1083X\nTS-h977XU-RP/TS-h1277XU-RP",
            "20201031-h4.5.1.1472",
        )
        self.assertTrue(
            "QuTS hero" == product
            and "" == platform
            and "h4.5.1.1472 build 20201031" == ver_n_bld
            and "h4.5.x" == ver_begin
        )

    def test_parse_fw_delivery_process_62(self):
        product, platform, ver_n_bld, ver_begin = parse_fw_delivery_process(
            "HEROMANP-952",
            "TS-h2490FU\nTS-h3088XU\nTVS-h1288X/TVS-h1688X\nTS-h686/TS-h886\nTS-h1886XU\nTS-h1283XU/TS-h1683XU/TS-h2483XU\nTNS-h1083X\nTS-h977XU-RP/TS-h1277XU-RP\nTS-h973AX",
            "1582",
        )
        self.assertTrue(
            "QuTS hero" == product
            and "" == platform
            and "1582" == ver_n_bld
            and "0000" == ver_begin
        )

    def test_parse_fw_delivery_process_63(self):
        product, platform, ver_n_bld, ver_begin = parse_fw_delivery_process(
            "HEROMANP-4325",
            "X90U: TS-h2490FU/TS-h1090FU\nX90: TS-h1290FX\nX89FU: TDS-h2489FU",
            "QuTS hero h5.1.5.2647 build 20240118",
        )
        self.assertTrue(
            "QuTS hero" == product
            and "" == platform
            and "h5.1.5.2647 build 20240118" == ver_n_bld
            and "h5.1.x" == ver_begin
        )

    def test_parse_fw_delivery_process_70(self):
        product, platform, ver_n_bld, ver_begin = parse_fw_delivery_process(
            "QVPMANPJ-1116", "QVP-21A, QVP-41A, QVP-41B, QVP-63A, QVP-85A", "2.1.3.0"
        )
        self.assertTrue(
            "QVR Pro Appliance" == product
            and "QVP-21A, QVP-41A, QVP-41B, QVP-63A, QVP-85A" == platform
            and "2.1.3.0" == ver_n_bld
            and "2.0.0" == ver_begin
        )

    def test_parse_fw_delivery_process_71(self):
        product, platform, ver_n_bld, ver_begin = parse_fw_delivery_process(
            "QVPMANPJ-1468",
            "QVP-21A, QVP-41A, QVP-41B, QVP-63A, QVP-63B, QVP-85A, QVP-85B",
            "20230421",
            (
                "\\\\172.17.23.188\\QNAP_Software\\daily_build\\QVP_2.3.1\\0476\\\n"
                "2135507294 1885414829 QVP-21A_20230421-2.3.1.0476.img\n"
                "4209080428 1894989376 QVP-XXA_20230421-2.3.1.0476.img\n"
                "2331532300 1888633928 QVP-41B_20230421-2.3.1.0476.img\n"
                "1440178043 1888818871 QVP-XXB_20230421-2.3.1.0476.img"
            ),
        )
        self.assertTrue(
            "QVR Pro Appliance" == product
            and "QVP-21A, QVP-41A, QVP-41B, QVP-63A, QVP-63B, QVP-85A, QVP-85B"
            == platform
            and "2.3.1.0476" == ver_n_bld
            and "2.0.0" == ver_begin
        )

    def test_parse_fw_delivery_process_72(self):
        product, platform, ver_n_bld, ver_begin = parse_fw_delivery_process(
            "QVPMANPJ-1507",
            "QVP-21A, QVP-41A, QVP-41B, QVP-63A, QVP-85A, QVP-63B, QVP-85B, QVP-21C, QVP-41C",
            "20230616",
            filelink="679379497 1885503798 QVP-21A_20230616-2.3.2.0532.img\n3980682379 1894809544 QVP-XXA_20230616-2.3.2.0532.img\n2320505310 1888296552 QVP-41B_20230616-2.3.2.0532.img\n385704145 1888858609 QVP-XXB_20230616-2.3.2.0532.img\n4222270921 1889141591 QVP-XXC_20230616-2.3.2.0532.img",
        )
        self.assertTrue(
            "QVR Pro Appliance" == product
            and "QVP-21A, QVP-41A, QVP-41B, QVP-63A, QVP-85A, QVP-63B, QVP-85B, QVP-21C, QVP-41C"
            == platform
            and "2.3.2.0532 build 20230616" == ver_n_bld
            and "2.3.x" == ver_begin
        )

    def test_parse_fw_delivery_process_80(self):
        product, platform, ver_n_bld, ver_begin = parse_fw_delivery_process(
            "QESMANPJ-5605",
            "ES1640dc v2; ES1686dc; TDS-16489U-R2; TES-1885U; TES-3085U;ES2486dc",
            "ES-DUAL_20220107-2.2.0.1053_v5 / ES-SINGLE_20220107-2.2.0.1041_v5",
        )
        self.assertTrue(
            "QES" == product
            and "ES1640dc v2; ES1686dc; TDS-16489U-R2; TES-1885U; TES-3085U;ES2486dc"
            == platform
            and "2.2.0 build 20220107" == ver_n_bld
            and "2.2.0" == ver_begin
        )

    def test_parse_fw_delivery_process_90(self):
        product, platform, ver_n_bld, ver_begin = parse_fw_delivery_process(
            "QNEMANPJ-953",
            "<QuCPE>\n- QuCPE-3034 (對外出貨用): QuCPE-3034-C3758R..",
            "1.0.3.q530",
        )
        self.assertTrue(
            "QNE" == product
            and "" == platform
            and "1.0.3.q530" == ver_n_bld
            and "1.0.0" == ver_begin
        )

    def test_parse_fw_delivery_process_100(self):
        product, platform, ver_n_bld, ver_begin = parse_fw_delivery_process(
            "NVRQVRSV-477", "請參考fw檔案清單", "5.1.6 (2022/04/01)"
        )
        self.assertTrue(
            "QVR" == product
            and "" == platform
            and "5.1.6 build 20220401" == ver_n_bld
            and "5.1.0" == ver_begin
        )

    def test_parse_fw_delivery_process_101(self):
        product, platform, ver_n_bld, ver_begin = parse_fw_delivery_process(
            "NVRQVRSV-518",
            "Legacy NVR",
            "5.1.6",
            filelink="\\\\172.17.23.188\\QNAP_Software\\daily_build\\QVR_5.1.6\\0684\\\nVS-12140UPro_20231115-5.1.6.img\nVS-12140UPro+_20231115-5.1.6.img\nVS-12148UPro_20231115-5.1.6.img\nVS-12148UPro+_20231115-5.1.6.img",
        )
        self.assertTrue(
            "QVR" == product
            and "" == platform
            and "5.1.6 build 20231115" == ver_n_bld
            and "5.1.0" == ver_begin
        )

    def test_parse_fw_delivery_process_110(self):
        product, platform, ver_n_bld, ver_begin = parse_fw_delivery_process(
            "ODMODMMP-217", "TS-464-8G-tekwind", "5.0.0.2527#20230915", filelink=None
        )
        self.assertTrue(
            "QTS" == product
            and "Generic" == platform
            and "5.0.0.2527 build 20230915" == ver_n_bld
            and "5.0.0" == ver_begin
        )


class ParseFwReleaseProcessQtsBuildTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_parse_fw_release_process_10(self):
        product, platform, ver_n_bld, ver_begin = parse_fw_release_process(
            "NVRQVRSV-281",
            "Release Test - QVR FW 5.1.5 build 20210803 (Round 1)",
            "20210803",
        )
        self.assertTrue(
            "QVR" == product and "" == platform,
            "5.1.5 build 20210803" == ver_n_bld and "5.x.x" == ver_begin,
        )


class ParseAppReleaseProcessQtsBuildTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    """
    def test_parse_app_release_process_10(self):
        product, platform, version = parse_app_release_process('NVRQUSC2-207', 'QUSBCam2', 'QuTS hero 4.5.3', '1.1.4_20210730')
        self.assertTrue(''==product and ''==platform and ''==version)
    
    def test_parse_app_release_process_20(self):
        product, platform, version = parse_app_release_process('NVRQUSC2-207', 'QUSBCam2', 'QTS 4.5.4', '2.0.1_20210803 & 2.0.1_20210804')
        self.assertTrue(''==product and ''==platform and ''==version)
    """


class ParseStorePublishProcessQtsBuildTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_parse_store_publish_process_10(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "NVRQUSC2-207", "QUSBCam2", "QuTS hero 4.5.3", "1.1.4_20210730"
        )
        self.assertTrue(
            "QUSBCam2" == product
            and "QuTS hero 4.5.3" == platform
            and "1.1.4 ( 2021/07/30 )" == version
            and "1.1.x" == ver_begin
        )

    def test_parse_store_publish_process_20(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "NVRQUSC2-207", "QUSBCam2", "QTS 4.5.4", "2.0.1_20210803 & 2.0.1_20210804"
        )
        self.assertTrue(
            "QUSBCam2" == product
            and "QTS 4.5.4" == platform
            and "2.0.1 ( 2021/08/03 )" == version
            and "2.0.x" == ver_begin
        )

    def test_parse_store_publish_process_21(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "NVRQUSC2-441",
            " QUSBCam2",
            None,
            "2.0.3",
            filelink="\\\\172.17.23.188\\QNAP_Software\\daily_build\\QUSBCam2_2.0.3\\\nqusbcam2_2.0.3_20230615_x86_64.qpkg\nqusbcam2_2.0.3_20230607_arm_64.qpkg\nqusbcam2_2.0.3_20230606_arm_al.qpkg",
        )
        self.assertTrue(
            "QUSBCam2" == product
            and "" == platform
            and "2.0.3 ( 2023/06/15 )" == version
            and "2.0.3" == ver_begin
        )

    def test_parse_store_publish_process_30(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "KIBKCAAN-192", "KoiCast", "", "1.1.1 build 20210629"
        )
        self.assertTrue(
            "KoiCast" == product
            and "" == platform
            and "1.1.1 build 20210629" == version
            and "1.1.x" == ver_begin
        )

    def test_parse_store_publish_process_40(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QSSNSGD0-371",
            "QuNetSwitch",
            "This QPKG is only used for QGD-1600P",
            "1.0.6.1509",
        )
        self.assertTrue(
            "QuNetSwitch" == product
            and "QGD-1600P" == platform
            and "1.0.6.1509" == version
            and "1.0.x" == ver_begin
        )

    def test_parse_store_publish_process_50(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTSMQC00-177", "myQNAPcloud Link", "QuTS Hero", "2.2.21_20210510"
        )
        self.assertTrue(
            "myQNAPcloud Link" == product
            and "QuTS Hero" == platform
            and "2.2.21 ( 2021/05/10 )" == version
            and "2.2.x" == ver_begin
        )

    def test_parse_store_publish_process_51(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTSMQC00-1004",
            "myQNAPcloud",
            None,
            "1.0.52",
            filelink="//172.17.25.251/Daily_Build/Cloud_Dept/myQNAPcloud/1.0.52/\nMyCloudNas_1.0.52_20231124_arm_al.qpkg\nMyCloudNas_1.0.52_20231124_arm_64.qpkg\nMyCloudNas_1.0.52_20231124_x86_64.qpkg",
        )
        self.assertTrue(
            "myQNAPcloud" == product
            and "" == platform
            and "1.0.52 ( 2023/11/24 )" == version
            and "1.0.x" == ver_begin
        )

    def test_parse_store_publish_process_52(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTSMQC00-963",
            "myQNAPcloud Link",
            None,
            "2.4.51",
            filelink="//172.17.25.251/Daily_Build/Cloud_Dept/CloudLink/2.4.51/\nCloudLink_2.4.51_20231030_x86_64.qpkg\nCloudLink_2.4.51_20231030_arm_ms.qpkg\nCloudLink_2.4.51_20231030_arm_kw.qpkg\nCloudLink_2.4.51_20231030_arm_64.qpkg\nCloudLink_2.4.51_20231030_arm_al.qpkg",
        )
        self.assertTrue(
            "myQNAPcloud Link" == product
            and "" == platform
            and "2.4.51" == version
            and "2.4.x" == ver_begin
        )

    def test_parse_store_publish_process_60(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTSHBS00-2527",
            "Hybrid Backup Sync",
            "",
            "17.0.0726",
            filelink="smb://172.17.25.251/Daily_Build/Solution_Team/Hybrid_Backup_Sync/DailyBuild_Backup/Hybrid_Backup_Sync_3/2021/May/12/",
        )
        self.assertTrue(
            "Hybrid Backup Sync" == product
            and "" == platform
            and "17.0.0726" == version
            and "17.0.x" == ver_begin
        )

    def test_parse_store_publish_process_61(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTSHBS00-2462",
            "Hybrid Backup Sync",
            None,
            "Hybrid_Backup_Sync_3/2021/May/07/special_fw436",
            filelink="smb://172.17.25.251/Daily_Build/Solution_Team/Hybrid_Backup_Sync/DailyBuild_Backup/Hybrid_Backup_Sync_3/2021/May/07/special_fw436/",
        )
        self.assertTrue(
            "Hybrid Backup Sync" == product
            and "" == platform
            and "3.0" == version
            and "3.x" == ver_begin
        )

    def test_parse_store_publish_process_70(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTSPTST0-653",
            "Photo Station",
            "",
            "20210819",
            filelink="\\\\172.17.21.5\\pub\\daily_build\\PhotoStation\\2021\\Aug\\19\\PhotoStation_5.7.13_20210819_all.qpkg",
        )
        self.assertTrue(
            "Photo Station" == product
            and "" == platform
            and "5.7.13 ( 2021/08/19 )" == version
            and "5.7.x" == ver_begin
        )

    def test_parse_store_publish_process_71(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTSPTST0-774",
            "Photo Station",
            "",
            "20220114",
            filelink=None,
            summary="[QNAP live update (not include iOS ipa)] Photo Station 5.7.15 release test for QTS 4.3.6",
        )
        self.assertTrue(
            "Photo Station" == product
            and "" == platform
            and "5.7.15 ( 2022/01/14 )" == version
            and "5.7.x" == ver_begin
        )

    def test_parse_store_publish_process_80(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "NVRSTGEP-52",
            "NVR Storage Expansion",
            "",
            "1.0.6",
            filelink="\\\\172.17.23.188\\QNAP_Software\\Firmware\\StorageExpansion\\1.0.6_Build_20210803",
        )
        self.assertTrue(
            "NVR Storage Expansion" == product
            and "" == platform
            and "1.0.6 ( 2021/08/03 )" == version
            and "1.0.x" == ver_begin
        )

    def test_parse_store_publish_process_81(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "NVRSTGEP-38", "NVR Storage Expansion", "全部FW", None, filelink="下架"
        )
        self.assertTrue(
            "NVR Storage Expansion" == product
            and "" == platform
            and "1.0.5" == version
            and "1.0.x" == ver_begin
        )

    def test_parse_store_publish_process_90(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTSIMTP0-135",
            "Image2PDF",
            "",
            "20210817-fecb0ce",
            filelink="\\\\172.17.25.251\\Daily_Build\\QTS_Team\\QPKG\\Img2PDF\\Release\\v2.1.5-20210817",
        )
        self.assertTrue(
            "Image2PDF" == product
            and "" == platform
            and "2.1.5 ( 2021/08/17 )" == version
            and "2.1.x" == ver_begin
        )

    def test_parse_store_publish_process_100(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTSMSAO0-401",
            "Media Streaming add-on",
            "QTS 5.0.0",
            "500.0.0.3",
            filelink="\\\\172.17.25.251\\Daily_Build\\VideoProductRMD_Team\\sw7\\MediaStreamingAddOn\\5.0.x\\500.0.0.3\\0x0aMediaStreamingAdd-on_500.0.0.3_x86_64_20210820.qpkg0x0aMediaStreamingAdd-on_500.0.0.3_arm_64_20210820.qpkg0x0aMediaStreamingAdd-on_500.0.0.3_arm_al_20210820.qpkg",
        )
        self.assertTrue(
            "Media Streaming add-on" == product
            and "QTS 5.0.0" == platform
            and "500.0.0.3 ( 2021/08/20 )" == version
            and "500.0.x" == ver_begin
        )

    def test_parse_store_publish_process_110(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "AFOTKAND-307",
            "KoiTalk",
            "KoiTalk Android 2.5.0",
            "#23",
            filelink="http://192.168.69.80:8888/view/KoiTalk/job/KoiTalk-Android_v2.5/23/artifact/app/build/outputs/bundle/prodP2pRelease/KoiTalk2.5.1.23-prod-p2p-release.aab",
        )
        self.assertTrue(
            "KoiTalk" == product
            and "Android" == platform
            and "2.5.1" == version
            and "2.5.x" == ver_begin
        )

    def test_parse_store_publish_process_111(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "AFOTKAND-320", "KoiTalk", None, "v2.5.2", filelink="Please provide"
        )
        self.assertTrue(
            "KoiTalk" == product
            and "" == platform
            and "2.5.2" == version
            and "2.5.x" == ver_begin
        )

    def test_parse_store_publish_process_120(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "CMNMINIS-41",
            "MinimServer",
            "",
            "2.0.19",
            filelink="\\\\172.17.25.251\\Daily_Build\\3rd-Party_QPKGs\\MinimServer\nMinimServer-2.0.19-intel.qpkg\nMinimServer-2.0.19-arm64.qpkg\nMinimServer-2.0.19-armv7.qpkg",
        )
        self.assertTrue(
            "MinimServer" == product
            and "" == platform
            and "2.0.19" == version
            and "2.0.x" == ver_begin
        )

    def test_parse_store_publish_process_130(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTSMTMC0-2113",
            "Multimedia Console",
            "",
            "1.4.3",
            filelink="\\\\172.17.25.251\\Daily_Build\\VideoProductRMD_Team\\sw7\\MultimediaConsole\\2021\\10\\05\nMultimediaConsole_1.4.3_20211005_5_arm_al.qpkg\nMultimediaConsole_1.4.3_20211005_5_arm64.qpkg\nMultimediaConsole_1.4.3_20211005_5_x86_64.qpkg",
        )
        self.assertTrue(
            "Multimedia Console" == product
            and "" == platform
            and "1.4.3 ( 2021/10/05 )" == version
            and "1.4.x" == ver_begin
        )

    def test_parse_store_publish_process_140(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "NVRSVLST-741",
            "Surveillance Station",
            "QTS 5.0",
            "5.2.0.4.2",
            filelink="\\\\172.17.23.188\\QNAP_Software\\Firmware\\2021\\Oct\26\\QPKG_NSS\\\nSurveillanceStation_5.2.0.4.2_20211026_arm_64.qpkg\nSurveillanceStation_5.2.0.4.2_20211026_x86_64.qpkg",
        )
        self.assertTrue(
            "Surveillance Station" == product
            and "QTS 5.0" == platform
            and "5.2.0.4.2 ( 2021/10/26 )" == version
            and "5.2.x" == ver_begin
        )

    def test_parse_store_publish_process_150(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTSMAG00-558",
            "QmailAgent",
            "FW 4.5.3, 4.5.4",
            "20210825",
            filelink="smb://172.17.25.251/Daily_Build/Solution_Team/Qmail/DailyBuild_Qmail/3.0.2/20210825",
        )
        self.assertTrue(
            "QmailAgent" == product
            and "QTS 4.5" == platform
            and "3.0.2 ( 2021/08/25 )" == version
            and "3.0.x" == ver_begin
        )

    def test_parse_store_publish_process_151(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTSMAG00-562",
            "QmailAgent",
            "FW h4.5.4",
            "20210825",
            filelink="smb://172.17.25.251/Daily_Build/Solution_Team/Qmail/DailyBuild_Qmail/3.0.2/20210825",
        )
        self.assertTrue(
            "QmailAgent" == product
            and "QuTS hero h4.5.4" == platform
            and "3.0.2 ( 2021/08/25 )" == version
            and "3.0.x" == ver_begin
        )

    def test_parse_store_publish_process_160(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "ANDCTZ00-144",
            "AND Qcontactz",
            "",
            "Qcontactz-1.4.0.0.20210907-20210907-production.apk",
            filelink="http://172.17.37.201:8089/job/(Android)%20Qcontactz%20v1.4.0_2020/lastSuccessfulBuild/artifact/MyContacts/mycontacts/build/outputs/apk/production/release/Qcontactz-1.4.0.0.20210907-20210907-production.apk",
        )
        self.assertTrue(
            "Qcontactz" == product
            and "" == platform
            and "1.4.0.0.20210907" == version
            and "1.4.x" == ver_begin
        )

    def test_parse_store_publish_process_170(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "CMNLINKS-61",
            "KazooServer",
            "",
            "4.11.20",
            filelink="\\\\172.17.25.251\\Daily_Build\3rd-Party_QPKGs\\KazooServer\4.11.20\\\nKazooServer_4.11.20_qnap-x86_64.qpkg\nKazooServer_4.11.20_qnap-arm_64.qpkg",
        )
        self.assertTrue(
            "Kazoo Server" == product
            and "" == platform
            and "4.11.20" == version
            and "4.11.x" == ver_begin
        )

    def test_parse_store_publish_process_180(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "ANDFLAD0-1622",
            "Qfile Android 3.0.0",
            "",
            "3.0.0.1105",
            filelink="https://app.qnaprd3.tk/Beta/QNAP/Qfile/Android/3.0.0/QNAPQfileAndroid-3.0.0.1105.apk",
        )
        self.assertTrue(
            "Qfile" == product
            and "" == platform
            and "3.0.0.1105" == version
            and "3.0.x" == ver_begin
        )

    def test_parse_store_publish_process_190(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "NVRVRLIT-1922",
            "QVR Elite",
            "for hero h4.5.4",
            "2.1.4.0",
            filelink="\\\\172.17.23.188\\QNAP_Software\\Firmware\\2021\\Dec\\06\\ubuntu1804\\QELT_B20210412_210_V2140\\QVREliteServer_2.1.4.0_20211206_x86_64.qpkg",
        )
        self.assertTrue(
            "QVR Elite" == product
            and "QuTS hero h4.5.4" == platform
            and "2.1.4.0 (2021/12/06)" == version
            and "2.1.x" == ver_begin
        )

    def test_parse_store_publish_process_191(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "NVRVRLIT-1922",
            "QVR Elite",
            "for hero h5.0",
            "2.1.4.0",
            filelink="\\\\172.17.23.188\\QNAP_Software\\Firmware\\2021\\Dec\\06\\ubuntu1804\\QELT_B20210412_210_V2140\\QVREliteServer_2.1.4.0_20211206_x86_64.qpkg",
        )
        self.assertTrue(
            "QVR Elite" == product
            and "QuTS hero h5.0.0" == platform
            and "2.1.4.0 (2021/12/06)" == version
            and "2.1.x" == ver_begin
        )

    def test_parse_store_publish_process_200(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QVRPRGRD-4440",
            "QVR Pro",
            "For QTS 4.5.4",
            "2.1.3.0",
            filelink="\\\\172.17.23.188\\QNAP_Software\\Firmware\\2021\\Dec\06\\ubuntu1804\\QVRPRO_B20210412_210_V2130\\\nQVRProServer_2.1.3.0_20211206_x86_64.qpkg\nQVRProServer_2.1.3.0_20211206_arm64.qpkg",
        )
        self.assertTrue(
            "QVR Pro" == product
            and "QTS 4.5.4" == platform
            and "2.1.3.0 (2021/12/06)" == version
            and "2.1.x" == ver_begin
        )

    def test_parse_store_publish_process_210(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QVRPRGRD-4436",
            "QVR Guard",
            "For QTS 4.5.4",
            "2.1.3.0",
            filelink="\\\\172.17.23.188\\QNAP_Software\\Firmware\\2021\\Dec\\06\\ubuntu1804\\Guard_B20210412_210_V2130\\\nQVRGuard_2.1.3.0_20211206_x86_64.qpkg",
        )
        self.assertTrue(
            "QVR Guard" == product
            and "QTS 4.5.4" == platform
            and "2.1.3.0 (2021/12/06)" == version
            and "2.1.x" == ver_begin
        )

    def test_parse_store_publish_process_220(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTSQKLAG-102",
            "QcalAgent",
            None,
            "1.1.7",
            filelink="\\\\172.17.25.251\\Daily_Build\\ANP_Team\\SW5\\QTSApp\\Qcalendar\\qcalendar_1.1.7_20211210104300_x86.qpkg",
        )
        self.assertTrue(
            "QcalAgent" == product
            and "" == platform
            and "1.1.7" == version
            and "1.1.x" == ver_begin
        )

    def test_parse_store_publish_process_230(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTSPXSV0-149",
            "Proxy Server",
            "QTS 4.5.x",
            "1.4.2",
            filelink="//172.17.25.251/Daily_Build/ANP_Team/SW5/QTSApp/ProxyServer/\nProxyServer_1.4.2_arm_64_20211230095750.qpkg\nProxyServer_1.4.2_x41_20211230095758.qpkg\nProxyServer_1.4.2_x86_64_20211230095738.qpkg",
        )
        self.assertTrue(
            "Proxy Server" == product
            and "QTS 4.5.x" == platform
            and "1.4.2 ( 2021/12/30 )" == version
            and "1.4.x" == ver_begin
        )

    def test_parse_store_publish_process_231(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTSPXSV0-166",
            "Proxy Server",
            "h5.0.0",
            "1.4.3",
            filelink="//172.17.25.251/Daily_Build/ANP_Team/SW5/QTSApp/ProxyServer/\nProxyServer_1.4.3_x86_64_20220118163830.qpkg",
        )
        self.assertTrue(
            "Proxy Server" == product
            and "QuTS hero h5.0.0" == platform
            and "1.4.3 ( 2022/01/18 )" == version
            and "1.4.x" == ver_begin
        )

    def test_parse_store_publish_process_240(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "ANDSCAP0-145",
            "Qsirch",
            None,
            "Qsirch-1.5.0.0.5efbc49-20200623",
            filelink="http://172.17.37.201:8089/job/(Android)%20Qsirch_v1.5.0/38/artifact/Qsirch/app/build/outputs/apk/production/release/Qsirch-1.5.0.0.5efbc49-20200623-production.apk",
        )
        self.assertTrue(
            "Qsirch" == product
            and "Android" == platform
            and "1.5.0.0.20200623" == version
            and "1.5.x" == ver_begin
        )

    def test_parse_store_publish_process_250(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "CLDVCLD0-2271",
            "Mattermost",
            None,
            "5.0.0.8",
            filelink="\\\\172.17.25.251\\Daily_Build\\ANP_Team\\SW5\\QTSApp\\mattermost\\mattermost_5.0.0.8_4b6db41.qpkg",
        )
        self.assertTrue(
            "Mattermost" == product
            and "" == platform
            and "5.0.0.8" == version
            and "5.0.x" == ver_begin
        )

    def test_parse_store_publish_process_260(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTSVDOST-767",
            "Video Station",
            None,
            "5.5.9",
            filelink="\\\\172.17.21.5\\pub\\daily_build\\VideoStationPro\\2022\\Feb\\16\\nVideoStationPro_5.5.9_20220216_all.qpkg",
        )
        self.assertTrue(
            "Video Station" == product
            and "" == platform
            and "5.5.9 ( 2022/02/16 )" == version
            and "5.5.x" == ver_begin
        )

    def test_parse_store_publish_process_261(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTSVDOST-658",
            "Video Station",
            None,
            "20220113",
            filelink=None,
            summary="[QNAP live update (not include iOS ipa)] VideoStation v5.5.8 release test for QTS 5.0",
        )
        self.assertTrue(
            "Video Station" == product
            and "" == platform
            and "5.5.8 ( 2022/01/13 )" == version
            and "5.5.x" == ver_begin
        )

    def test_parse_store_publish_process_270(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTSDLST0-355",
            "Download Station",
            None,
            "5.7.0.194",
            filelink="\\\\172.17.21.5\\pub\\daily_build\\QTS_4.5.4\\1956\nDownloadStation_5.7.0.194_20220222_x86_64.qpkg\nDownloadStation_5.7.0.194_20220222_arm_64.qpkg\nDownloadStation_5.7.0.194_20220222_arm_al.qpkg",
        )
        self.assertTrue(
            "Download Station" == product
            and "" == platform
            and "5.7.0.194 ( 2022/02/22 )" == version
            and "5.7.x" == ver_begin
        )

    def test_parse_store_publish_process_280(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTSVPNSV-2238", "QVPN Service", None, "QVPN 3.0.760", filelink=None
        )
        self.assertTrue(
            "QVPN Service" == product
            and "" == platform
            and "3.0.760" == version
            and "3.0.x" == ver_begin
        )

    def test_parse_store_publish_process_290(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "VAPROONS-180",
            "Roon Server",
            None,
            "2021-05-18",
            filelink="https://drive.google.com/file/d/1SjN5xziViYI5lRciBbg3XJf1GIlY5rdw/view?usp=sharing",
        )
        self.assertTrue(
            "Roon Server" == product
            and "" == platform
            and "2021-05-18" == version
            and "2021-xx-xx" == ver_begin
        )

    def test_parse_store_publish_process_300(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "ANDQMGAD-2184",
            "QuMagie Mobile for Android",
            None,
            "1.6.0.0.20220531",
            filelink="https://sauron.qnap.com/sw5-mobile-project/android/qumagie-android/-/jobs/209004/artifacts/download?file_type=archive",
        )
        self.assertTrue(
            "QuMagie" == product
            and "" == platform
            and "1.6.0" == version
            and "1.x.x" == ver_begin
        )

    def test_parse_store_publish_process_301(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "ANDQMGAD-4021",
            "QuMagie Mobile for Android",
            None,
            "2.2.0",
            filelink="https://app.qnaprd3.tk/Beta/QNAP/QuMagie/Android/2.2.0/QNAPQuMagieAndroid-2.2.0.0126.apk",
        )
        print(product)
        print(platform)
        print(version)
        print(ver_begin)
        self.assertTrue(
            "QuMagie Mobile for Android" == product
            and "" == platform
            and "2.2.0.0126" == version
            and "2.2.x" == ver_begin
        )

    def test_parse_store_publish_process_310(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QWSMAND0-1184",
            "QuRouter",
            None,
            "1.2.0.0518",
            filelink="1. Global: 1.2.0.0518(Google Play 內部測試版)apk:https://ieinet-my.sharepoint.com/personal/lukeyang_qnap_com/_layouts/15/onedrive.aspx?id=%2Fpersonal%2Flukeyang%5Fqnap%5Fcom%2FDocuments%2FMicrosoft%20Teams%20Chat%20Files%2FQuRouter%2D1%2E2%2E0%2E0518%2D344%2Dglobal%2Drelease%2Eapk&parent=%2Fpersonal%2Flukeyang%5Fqnap%5Fcom%2FDocuments%2FMicrosoft%20Teams%20Chat%20Files&ga=1",
        )
        self.assertTrue(
            "QuRouter" == product
            and "" == platform
            and "1.2.0" == version
            and "1.x.x" == ver_begin
        )

    def test_parse_store_publish_process_320(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTS00000-11556",
            "Cinema28",
            None,
            "1.2.3",
            filelink="\\\\172.17.25.251\\Daily_Build\\ANP_Team\\SW5\\QTSApp\\Cinema28\\Cinema28_1.2.3_20210909_99999.qpkg",
        )
        self.assertTrue(
            "Cinema28" == product
            and "" == platform
            and "1.2.3 ( 2021/09/09 )" == version
            and "1.2.x" == ver_begin
        )

    def test_parse_store_publish_process_330(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTSQMAGI-1952",
            "qumagie",
            None,
            "1.6.2",
            filelink=None,
            summary="[QNAP live update (not include iOS ipa)] QuMagie 1.6.2 Release on QuTS hero 4.5.x",
        )
        self.assertTrue(
            "QuMagie" == product
            and "" == platform
            and "1.6.2" == version
            and "1.6.x" == ver_begin
        )

    def test_parse_store_publish_process_340(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "KIBKMIOS-171",
            "KoiMeeter",
            None,
            "KoiMeeter 1.2.0 (202205311919)",
            filelink="TestFlight : KoiMeeter 1.2.0 (202205311919)",
            summary="[iOS APP Store] KoiMeeter Mobile iOS 1.2.0 release test 2nd 2022/05/31",
        )
        self.assertTrue(
            "KoiMeeter" == product
            and "" == platform
            and "1.2.0 ( 2022/05/31 )" == version
            and "1.2.x" == ver_begin
        )

    def test_parse_store_publish_process_350(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTSVPNWS-293",
            "QVPN Windows",
            None,
            "2.0.0.1310 and 2.0.0.1316",
            filelink="https://app.qnaprd3.tk/Beta/QNAP/QVPN/Windows/2.0.0/QNAPQVPNWindows-2.0.0.1310.exe",
            summary="[QNAP live update] [QVPN] QVPN Utility 2.0.0 release for Windows",
        )
        self.assertTrue(
            "QVPN Windows" == product
            and "" == platform
            and "2.0.0.1310" == version
            and "2.0.x" == ver_begin
        )

    def test_parse_store_publish_process_360(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTSQULCT-1366",
            "QuLog Center",
            None,
            "1.5.0.738",
            filelink="//172.17.21.5/pub/daily_build/QTS_5.0.1/2330/\nQuLog_1.5.0.738_20230306_arm_64.qpkg\nQuLog_1.5.0.738_20230306_arm_al.qpkg\nQuLog_1.5.0.738_20230306_x86_64.qpkg",
        )
        self.assertTrue(
            "QuLog Center" == product
            and "" == platform
            and "1.5.0.738 ( 2023/03/06 )" == version
            and "1.5.x.x" == ver_begin
        )

    def test_parse_store_publish_process_370(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "CMNQUFRW-1411",
            "QuFirewall",
            None,
            "2.3.3",
            filelink="\\\\172.17.25.251\\Daily_Build\ANP_Team\\SW5\\QTSApp\\qufirewall\\release_v2.3.3\\20230327\\",
        )
        self.assertTrue(
            "QuFirewall" == product
            and "" == platform
            and "2.3.3 ( 2023/03/27 )" == version
            and "2.3.x" == ver_begin
        )

    def test_parse_store_publish_process_380(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QVRPOCNT-5080",
            "QVR Pro Client",
            "Windows 10 SP1, Windows 11, Mac OS, and Mac M1",
            "2.3.0.0420",
            filelink="\\\\172.17.23.188\\QNAP_Software\\daily_build\\QVRProClient_2.3.0\\0420\\\nQVRProClientWinX86-2.3.0.0420.exe\nQVRProClientWinX64-2.3.0.0420.exe\nQVRProClientMac-2.3.0.0420.dmg",
        )
        self.assertTrue(
            "QVR Pro Client" == product
            and "Windows 10 SP1, Windows 11, Mac OS, and Mac M1" == platform
            and "2.3.0.0420" == version
            and "2.3.x.x" == ver_begin
        )

    def test_parse_store_publish_process_390(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTSMS000-823",
            "Music Station",
            None,
            "5.3.22",
            filelink="\\\\172.17.21.5\\pub\daily_build\\MusicStation\\2023\\May\\31\\",
        )
        self.assertTrue(
            "Music Station" == product
            and "" == platform
            and "5.3.22" == version
            and "5.3.x" == ver_begin
        )

    def test_parse_store_publish_process_391(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTSMS000-863",
            "Music Station",
            None,
            "MusicStation_4.8.11_20230822_all.qpkg",
            filelink="\\\\172.17.21.5\\pub\\daily_build\\MusicStation\\2023\\Aug\\22\\MusicStation_4.8.11_20230822_all.qpkg",
        )
        self.assertTrue(
            "Music Station" == product
            and "" == platform
            and "4.8.11" == version
            and "4.8.x" == ver_begin
        )

    def test_parse_store_publish_process_400(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTSCTST0-1415",
            "Container Station",
            None,
            "2.6.7.44",
            filelink="\\\\172.17.25.251\\Daily_Build\\ANP_Team\\Container_Station\\Release\\",
        )
        self.assertTrue(
            "Container Station" == product
            and "" == platform
            and "2.6.7.44" == version
            and "2.6.x.x" == ver_begin
        )

    def test_parse_store_publish_process_410(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "ANDQNOTE-770",
            "Qnotes3",
            None,
            "1.11.2.0.20230713",
            filelink="https://app.qnaprd3.ml/Beta/QNAP/Qnotes3/Android/1.11.2/Qnotes3-1.11.2.0.20230713.apk",
        )
        self.assertTrue(
            "Qnotes3" == product
            and "" == platform
            and "1.11.2.0 build ( 20230713 )" == version
            and "1.11.x.x" == ver_begin
        )

    def test_parse_store_publish_process_420(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "VAPQSYCT-1714",
            "Qsync Central",
            None,
            "4.4.0.15",
            filelink="\\\\172.17.21.5\\pub\\daily_build\\QTS_5.1.5\\2633\\\nQsyncServer_4.4.0.15_20240104_arm_64.qpkg\nQsyncServer_4.4.0.15_20240104_arm_al.qpkg\nQsyncServer_4.4.0.15_20240104_x86_hal.qpkg",
        )
        self.assertTrue(
            "Qsync Central" == product
            and "" == platform
            and "4.4.0.15 ( 2024/01/04 )" == version
            and "4.4.x.x" == ver_begin
        )

    def test_parse_store_publish_process_430(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "CMNQUFRW-1611",
            "QuFirewall",
            None,
            "2.4.1",
            filelink="\\\\172.17.25.251\\Daily_Build\\ANP_Team\\SW5\\QTSApp\\qufirewall\\daily_build\\v2.4.1\\20240201\nqufirewall_2.4.1_20240201090812_x86_64.qpkg\nqufirewall_2.4.1_20240201090812_arm_64.qpkg\nqufirewall_2.4.1_20240201090812_arm-x41.qpkg",
        )
        self.assertTrue(
            "QuFirewall" == product
            and "" == platform
            and "2.4.1 ( 2024/02/01 )" == version
            and "2.4.x" == ver_begin
        )

    def test_parse_store_publish_process_440(self):
        product, platform, version, ver_begin = parse_store_publish_process(
            "QTSNTSTN-1058",
            "Notes Station 3",
            "Recommend to use 2GB or above RAM",
            "3.9.6-20240423",
            filelink="\\\\172.17.21.5\\pub\\daily_build\\NotesStation3\\2024\Apr\\23\\\nNotesStation3_3.9.6-20240423_313934_v3.9.6_x86.qpkg\nNotesStation3_3.9.6-20240423_313934_v3.9.6_arm-x41.qpkg\nNotesStation3_3.9.6-20240423_313934_v3.9.6_arm-rtk.qpkg",
        )
        self.assertTrue(
            "Notes Station 3" == product
            and "" == platform
            and "3.9.6" == version
            and "3.9.x" == ver_begin
        )

