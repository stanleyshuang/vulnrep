# -*- coding: utf-8 -*-
#
# Author:   Stanley Huang
# Project:  vulnrep 2.0
# Date:     2022-04-13
#
from datetime import datetime
from dateutil import tz

from pkg._qjira.description import (
    extract_cweid,
    extract_capecid,
    extract_quality_score,
    extract_cvss_score,
)
from pkg._qjira.description import (
    extract_severity_level,
    extract_cveid,
    extract_sa_title,
)
from pkg._util.util_datetime import (
    local_to_local_str,
    local_str_to_local,
    duration_days,
)

from . import permanent_obj, permanent_objException


class analysisException(permanent_objException):
    pass


class analysis(permanent_obj):
    """
    analysis_obj:   {
                        'b_task_done':      the task is closed, no more effert needed
                        'b_done':           analysis done or not

                        'created':          date time in format '2021-05-13',
                        'validated':        date time in format '2021-05-13',
                        'duration':         the duration between created to done,

                        'summary':          analysis summary,\
                        'severity_level':   severity level,
                        'cveid':            CVE ID,

                        'cweids':           CWD ID array,
                        'capecids':         CAPEC ID array,
                        'cvssv3_vec':       CVSS vector,
                        'cvssv3_score':     CVSS score,
                        'description':      Description score,
                        'poc':              PoC score,
                        # 'suggestion':       Suggestion score,

                        'f_comment':        summary is commented,
                        'author':           the analyst,
                        'commented':        the request is commented,
                    }
    """

    def __init__(self, data, downloads, filename="analysis.json"):
        super(analysis, self).__init__(data, downloads, filename)
        self._b_use_ex = False

    def init(self, the_created_date, now):
        if self.json_obj is None:
            self.json_obj = {}
        if "b_task_done" not in self.json_obj:
            self.json_obj["b_task_done"] = False
        if "b_done" not in self.json_obj:
            self.json_obj["b_done"] = False
        if "created" not in self.json_obj:
            self.json_obj["created"] = local_to_local_str(
                the_created_date, format="%Y-%m-%d"
            )
        if "duration" not in self.json_obj or not self.json_obj["b_done"]:
            self.json_obj["duration"] = duration_days(the_created_date, now)

    def task_done(self, done_time):
        self.json_obj["b_task_done"] = True

    def analysis_done(self):
        self.json_obj["b_done"] = True

    def set_validated(self, time):
        validated_time = time.replace(tzinfo=tz.gettz("Asia/Taipei"))
        self.json_obj["validated"] = local_to_local_str(
            validated_time, format="%Y-%m-%d"
        )
        if "created" in self.json_obj:
            created_time = local_str_to_local(
                self.json_obj["created"], format="%Y-%m-%d"
            )
            self.json_obj["duration"] = duration_days(created_time, validated_time)

    def get_validated(self):
        if self.json_obj and "validated" in self.json_obj:
            return local_str_to_local(self.json_obj["validated"], format="%Y-%m-%d")
        return None

    def if_cwe_capec_cvss_exist(self):
        """
        if 'b_done' in self.json_obj and self.json_obj['b_done']:
            return True
        """
        if (
            "cweids" not in self.json_obj
            or "capecids" not in self.json_obj
            or "cvssv3_vec" not in self.json_obj
            or "cvssv3_score" not in self.json_obj
        ):
            return False
        if (
            "description" not in self.json_obj or "poc" not in self.json_obj
        ):  # or 'suggestion' not in self.json_obj:
            return False
        return True

    def if_summary_with_severity(self, summary):
        if summary.lower().find("[security]") >= 0:
            severity_level = extract_severity_level(summary)
            return severity_level is not None and len(severity_level) > 0
        return False

    @staticmethod
    def cve_json_callback(the_obj, cid, author, time, line):
        b_updated = False

        ### 解析 cweids, capecids, cvssv3_vec, cvssv3_score
        cweids = extract_cweid(line)
        capecids = extract_capecid(line)
        cvssv3_vec, cvssv3_score, b_40 = extract_cvss_score(line)

        if cweids or capecids or cvssv3_vec or cvssv3_score:
            if line.find("(EX)") >= 0 and the_obj._b_use_ex == False:
                the_obj._b_use_ex = True
                the_obj.json_obj.pop("cweids", None)
                the_obj.json_obj.pop("capecids", None)
                the_obj.json_obj.pop("cvssv3_vec", None)
                the_obj.json_obj.pop("cvssv3_score", None)

        if cweids:
            if "cweids" not in the_obj.json_obj:
                the_obj.json_obj["cweids"] = []
            for cweid in cweids:
                if cweid not in the_obj.json_obj["cweids"]:
                    # print("CWE ID: {cweid}".format(cweid=cweid))
                    the_obj.json_obj["cweids"].append(cweid)
                    b_updated = True

        if capecids:
            if "capecids" not in the_obj.json_obj:
                the_obj.json_obj["capecids"] = []
            for capecid in capecids:
                if capecid not in the_obj.json_obj["capecids"]:
                    # print("CAPEC ID: {capecid}".format(capecid=capecid))
                    the_obj.json_obj["capecids"].append(capecid)
                    b_updated = True

        if cvssv3_vec:
            # print("CVSSv3.1: vectorString {cvssv3_vec}".format(cvssv3_vec=cvssv3_vec))
            the_obj.json_obj["cvssv3_vec"] = cvssv3_vec
            b_updated = True

        if cvssv3_score:
            # print("CVSSv3.1: Score: {cvssv3_score}".format(cvssv3_score=cvssv3_score))
            the_obj.json_obj["cvssv3_score"] = cvssv3_score
            b_updated = True

        ### 解析 description, poc
        quality_score_keys = ["description", "poc", "steps", "content"]
        for quality_key in quality_score_keys:
            quality_score = extract_quality_score(quality_key, line)
            if quality_score:
                # print("CAPEC ID: {quality_score}".format(quality_score=quality_score))
                key_maps = {
                    "description": "description",
                    "poc": "poc",
                    "steps": "poc",
                    "content": "description",
                }
                the_obj.json_obj[key_maps[quality_key]] = quality_score
                b_updated = True

        if line.find("- CAPEC ID(s)") >= 0:
            the_obj.json_obj["commented"] = True

        if b_updated:
            ### 更新 validated, duration
            time = time.replace(tzinfo=tz.gettz("Asia/Taipei"))
            if "validated" in the_obj.json_obj:
                validated_time = local_str_to_local(
                    the_obj.json_obj["validated"], format="%Y-%m-%d"
                )
            else:
                validated_time = time
            if time >= validated_time:
                the_obj.json_obj["validated"] = local_to_local_str(
                    time, format="%Y-%m-%d"
                )
                if "created" in the_obj.json_obj:
                    created_time = local_str_to_local(
                        the_obj.json_obj["created"], format="%Y-%m-%d"
                    )
                    the_obj.json_obj["duration"] = duration_days(created_time, time)

    def update_cveid_severity_summary(
        self, summary, histories, reporter, task_created_date, sf_sub_report=None
    ):
        if sf_sub_report:
            self.json_obj['sf-sub-report'] = sf_sub_report

        if "cveid" in self.json_obj and len(self.json_obj["cveid"]) > 0:
            pass
        cveids = extract_cveid(summary)
        if cveids is None:
            self.json_obj["cveid"] = ""
        elif len(cveids) == 1:
            self.json_obj["cveid"] = cveids[0]
        else:
            # 多個 CVE IDs 可能是開源專案的揭露
            if (
                summary.lower().find("(3rd-party") >= 0
                or summary.lower().find("(internal") >= 0
            ):
                self.json_obj["cveid"] = "|".join(cveids)
            else:
                raise analysisException(
                    "non-3rd-party-multi-CVE-IDs", json_obj=self.json_obj
                )  # the case should be split..

        if self.is_comment() and "author" in self.json_obj:
            # CVE ID, Severity 已設定
            return True

        ### 更新資料並註記作者，時間
        author = None
        updated_date = None
        if self.if_summary_with_severity(summary):
            if histories:
                # Summary 格式符合，繼續檢查...
                for history in histories:
                    for item in history.items:
                        if "summary" == item.field:
                            if not self.if_summary_with_severity(
                                item.fromString
                            ) and self.if_summary_with_severity(item.toString):
                                author = history.author.name
                                updated_date = history.created[:10]
                                break
            else:
                # for unit test
                pass
        else:
            # Summary 格式不符合，等待 Securty Analyst 分析。
            return False

        if author is None or updated_date is None:
            # 開單人即是 Security Analyst
            author = reporter
            updated_date = task_created_date

        self.json_obj["f_comment"] = True

        ### 設定 summary, cveid, 3rd_party, severity_level
        if self.json_obj["cveid"] == "":
            # 研究員的發現可能非 QNAP 可以指定
            # 也有可能是獎金獵人
            self.analysis_done()
        elif self.json_obj["cveid"].find("|") < 0:
            # 有指定一個 CVE ID
            if summary.find("(3rd-party)") >= 0:
                self.analysis_done()
                self.json_obj["3rd_party"] = "Yes"
            # 要確定 CWE, CAPEC, CVSSv3, quality score 都收集到後才算結束。
        else:
            # 多個 CVE IDs 可能是開源專案的揭露
            if summary.find("(3rd-party)") >= 0:
                self.analysis_done()
                self.json_obj["3rd_party"] = "Yes"
        if "severity_level" not in self.json_obj:
            self.json_obj["severity_level"] = extract_severity_level(summary)
        if "author" not in self.json_obj and author:
            self.json_obj["author"] = author

        if updated_date:
            the_date = local_str_to_local(updated_date, format="%Y-%m-%d")
            the_date = the_date.replace(tzinfo=tz.gettz("Asia/Taipei"))

            if "validated" in self.json_obj:
                validated_time = local_str_to_local(
                    self.json_obj["validated"], format="%Y-%m-%d"
                )
            else:
                validated_time = the_date

            # 如果新的更新日期，比原來紀錄還新，更新花費時間
            if the_date >= validated_time:
                self.json_obj["validated"] = local_to_local_str(
                    the_date, format="%Y-%m-%d"
                )
                if "created" in self.json_obj:
                    created_time = local_str_to_local(
                        self.json_obj["created"], format="%Y-%m-%d"
                    )
                    self.json_obj["duration"] = duration_days(created_time, the_date)
        return True

    def request_info_msg(self, summary):
        author = self.json_obj["author"]
        # 兩個條件下，可以沒有 CWE ID，CAPEC ID 與 CVSSv3 資訊
        # 1. 沒有 CVE ID
        # 2. 此為第三方軟體
        if (
            "cveid" not in self.json_obj
            or len(self.json_obj["cveid"]) == 0
            or summary.lower().find("(3rd-party") >= 0
            or summary.lower().find("(internal") >= 0
        ):
            return None
        if "commented" in self.json_obj and self.json_obj["commented"]:
            return None
        # 否則如果沒有 CWE ID，CAPEC ID 或 CVSSv3，請分析師指派
        b_request_cwe = False
        b_request_capec = False
        b_request_cvssv3_vec = False
        b_request_cvssv3_score = False
        b_request_quality_scores = {}
        if "cweids" not in self.json_obj or len(self.json_obj["cweids"]) == 0:
            b_request_cwe = True
        """
        if 'capecids' not in self.json_obj or not self.json_obj['capecids'] or len(self.json_obj['capecids'])==0:
            b_request_capec = True
        """
        quality_score_keys = ["description", "poc"]
        for quality_key in quality_score_keys:
            if quality_key not in self.json_obj or not self.json_obj[quality_key]:
                b_request_quality_scores[quality_key] = True
        if "cvssv3_vec" not in self.json_obj:
            b_request_cvssv3_vec = True
        """
        if 'cvssv3_score' not in self.json_obj:
            b_request_cvssv3_score = True
        """
        quality_key_maps = {
            "description": "Content",
            "poc": "Steps",
        }
        if ("b_done" not in self.json_obj or not self.json_obj["b_done"]) and (
            "b_task_done" not in self.json_obj or not self.json_obj["b_task_done"]
        ):
            if (
                b_request_cwe
                or b_request_capec
                or b_request_cvssv3_vec
                or b_request_cvssv3_score
                or len(b_request_quality_scores) > 0
            ):
                msg = "[~{author}]\n請協助提供以下資訊：\n".format(author=author)
                if b_request_cwe:
                    msg += "   - CWE ID(s)\n"
                if b_request_capec:
                    msg += "   - CAPEC ID(s)\n"
                if b_request_cvssv3_vec:
                    msg += "   - CVSS vector\n"
                if b_request_cvssv3_score:
                    msg += "   - CVSS score\n"
                for quality_key in b_request_quality_scores:
                    msg += "   - {quality_key} score\n".format(
                        quality_key=quality_key_maps[quality_key]
                    )
                if (
                    not b_request_cwe
                    and not b_request_capec
                    and not b_request_cvssv3_vec
                    and not b_request_cvssv3_score
                ):
                    # quality score 沒有沒關係
                    self.json_obj["b_done"] = True
                return msg
        self.json_obj["b_done"] = True
        return None

    def is_done(self):
        if self.json_obj:
            if "b_done" in self.json_obj and self.json_obj["b_done"]:
                return True
            elif "b_task_done" in self.json_obj and self.json_obj["b_task_done"]:
                return True
        return False

    def is_analysis_done(self):
        if self.json_obj and "b_done" in self.json_obj:
            return self.json_obj["b_done"]
        return False

    def is_comment(self):
        if self.json_obj and "f_comment" in self.json_obj:
            return self.json_obj["f_comment"]
        return False

    def get_severity_level(self):
        if self.json_obj and "severity_level" in self.json_obj:
            return self.json_obj["severity_level"]
        return None

    def set_raw(self, raw):
        if self.json_obj:
            if "created" in self.json_obj:
                raw["triaged"] = self.json_obj["created"]
            if "duration" in self.json_obj:
                raw["triaged_duration"] = self.json_obj["duration"]
            if "b_done" in self.json_obj and self.json_obj["b_done"]:
                if "validated" in self.json_obj:
                    raw["validated"] = self.json_obj["validated"]
                if "summary" in self.json_obj:
                    raw["summary"] = self.json_obj["summary"]
                if "severity_level" in self.json_obj:
                    raw["severity_level"] = self.json_obj["severity_level"]
            if "cveid" in self.json_obj:
                raw["cveid"] = self.json_obj["cveid"]

            if "description" in self.json_obj:
                raw["description_score"] = self.json_obj["description"]
            if "poc" in self.json_obj:
                raw["poc_score"] = self.json_obj["poc"]
            """
            if 'suggestion' in self.json_obj:
                raw['suggestion_score'] = self.json_obj['suggestion']
            """
        return raw

    def retrieve_qsa(self, issuekey, qsa):
        # analysis_obj['cweids']
        # analysis_obj['capecids']
        # analysis_obj['cvssv3_vec']
        # analysis_obj['cvssv3_score']
        # analysis_obj['extracted_cveid']
        # analysis_obj['summary']
        # analysis_obj['severity_level']
        ### 確定 qsa 中，有 analysis 階層
        if "analysis" not in qsa:
            qsa["analysis"] = {}
        analysis_obj = qsa["analysis"]

        ### 指定 analysis 階層的參數
        analysis_obj["cweids"] = None
        analysis_obj["capecids"] = None
        analysis_obj["cvssv3_vec"] = None
        analysis_obj["cvssv3_score"] = None
        analysis_obj["extracted_cveid"] = None
        analysis_obj["summary"] = None
        analysis_obj["severity_level"] = None

        if self.json_obj:
            if "cweids" in self.json_obj:
                analysis_obj["cweids"] = self.json_obj["cweids"]

            if "capecids" in self.json_obj:
                analysis_obj["capecids"] = self.json_obj["capecids"]

            if "cvssv3_vec" in self.json_obj:
                analysis_obj["cvssv3_vec"] = self.json_obj["cvssv3_vec"]

            if "cvssv3_score" in self.json_obj:
                analysis_obj["cvssv3_score"] = self.json_obj["cvssv3_score"]

            if "cveid" in self.json_obj:
                analysis_obj["extracted_cveid"] = self.json_obj["cveid"]

            if "summary" in self.json_obj:
                analysis_obj["summary"] = self.json_obj["summary"]

            if "severity_level" in self.json_obj:
                analysis_obj["severity_level"] = self.json_obj["severity_level"]

        ### 將 qsa 位址回傳
        return qsa

    def dump(self):
        print("b_done: " + str(self.json_obj["b_done"]))
        if "cveid" in self.json_obj:
            print("cveid: " + self.json_obj["cveid"])
        if "cvssv3_vec" in self.json_obj:
            print("cvssv3_vec: " + self.json_obj["cvssv3_vec"])
        if "description" in self.json_obj:
            print("description score: " + str(self.json_obj["description"]))
        if "poc" in self.json_obj:
            print("poc score: " + str(self.json_obj["poc"]))
        if "severity_level" in self.json_obj:
            print("severity_level: " + self.json_obj["severity_level"])
