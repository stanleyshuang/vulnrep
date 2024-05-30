#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Author:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2021-06-13
#
import json, os, shutil
from datetime import datetime
from pkg._fdb.analysis import analysis
from pkg._util.util_datetime import pick_n_days_after, utc_to_local_str, duration_days

from . import i_issue, get_issuetype
from .comment import comment_parser, description_parser, content_filter
from .description import parse_salesforce_link, extract_model, extract_cveid


class task(i_issue):
    """
    Jira task
    """

    def __init__(self, jira, issue, debug_mode):
        super(task, self).__init__(jira, issue, debug_mode)
        if (
            get_issuetype(self.issue) != "Task"
            and get_issuetype(self.issue) != "Sub-task"
        ):
            raise Exception("Jira issuetype mismatch!!")
        if self.get_status_name() not in ["close", "abort"]:
            self.b_resolved = True
        self.mb_run_get_text = False
        self.mb_finding_response = False


class analysis_task(task):
    """
    Jira task for vulnerabilty analysis
    """

    def __init__(self, jira, issue, debug_mode):
        super(analysis_task, self).__init__(jira, issue, debug_mode)
        # salesforce data
        self.sf_data = {}
        self.sf_created_date = None

        # data flags & status for each phase
        self.analysis = None

        # Analysis Task
        self.fixing_date = None
        self.resolved_date = None
        self.verified_date = None
        self._closed_date = None
        self.verified_num = 0
        self.resolved_num = 0
        self.labtest_date = None
        self.release_date = None
        self.labtest_num = 0
        self.released_num = 0
        self.b_dependency_resolved = False
        self.bug_num = 0
        self.not_affected_num = 0
        self.assignee = None
        self._b_all_fixed = False
        self._b_one_fixed = False

        self._cve_json_url = None
        self.sf_sub_report = None

    @property
    def cve_json_url(self):
        return self._cve_json_url

    @cve_json_url.setter
    def cve_json_url(self, url):
        self._cve_json_url = url

    def get_sf_case_num(self):
        self.debuglog_i("[Task-{key}] Get SF Case Number".format(key=self.issue.key))
        description = self.issue.fields.description
        b_need_update, name, link, others = parse_salesforce_link(description)
        if len(name):
            sf_case_num = name.strip()
            return sf_case_num
        else:
            for label in self.issue.fields.labels:
                if label.find("SF:Q-") >= 0:
                    self.debuglog_i("             從 Label 讀取 " + label[3:])
                    return label[3:]
        return None

    def extract_sf_subject(self):
        if self.sf_sub_report:
            return self.sf_sub_report
        lines = self.issue.fields.description.split("\n")
        sf_subject = None
        for line in lines:
            if line.lower().find("[sf-sub-report]") >= 0:
                self.sf_sub_report = line.replace("[sf-sub-report]", "").strip()
                return self.sf_sub_report
            if sf_subject == None and line.find("[sf-subject]") >= 0:
                sf_subject = line.replace("[sf-subject]", "").strip()
        if sf_subject:
            self.sf_sub_report = sf_subject
            return self.sf_sub_report
        if self.sf_data and "subject" in self.sf_data:
            self.sf_sub_report = self.sf_data["subject"]
        return None

    def set_sf_data(self, created_date, researcher_email, researcher_name, sf_data):
        self.debuglog_i("[Task-{key}] Update SF Data".format(key=self.issue.key))
        if sf_data and "subject" in sf_data:
            summary = sf_data["subject"]
        else:
            summary = "n/a"
        # self.debuglog_r('--- Processing [Task-{key}] [{summary}]'.format(key=self.issue.key, summary=summary))

        # description 中有從 SF 帶過來的資料
        description = self.issue.fields.description
        b_need_update, sf_case_num, link, others = parse_salesforce_link(description)
        # 子單的 description 可能沒有 sf_case_num, link 資料，此時使用母單的資料
        if (
            (len(sf_case_num) == 0 or len(link) == 0)
            and sf_data
            and "description" in sf_data
        ):
            b, sf_case_num, link, dummy = parse_salesforce_link(sf_data["description"])

        s_format = "%Y-%m-%dT%H:%M:%S.000+0000"
        local_tz_str = "GMT"
        if created_date is None:
            created_date = self.issue.fields.created
            s_format = "%Y-%m-%dT%H:%M:%S.000+0800"
            local_tz_str = "Asia/Taipei"
        if sf_data == {}:
            sf_created_date, sf_created_date_str = self.get_time_n_str(
                created_date, s_format=s_format, local_tz_str=local_tz_str
            )
            sf_data = {
                "researcher_email": "",
                "researcher_name": "",
                "created_date": sf_created_date_str,
                "sf_case_num": sf_case_num,
            }
        ### Update Salesforce
        if sf_data and bool(sf_data):
            self.sf_data = sf_data
        if "sf_link" not in self.sf_data:
            self.sf_data["sf_link"] = link

        ### Update Salseforce link, researcher information in description
        if researcher_email and researcher_name:
            researcher_email_index = description.find(researcher_email)
            researcher_name_index = description.find(researcher_name)
            if b_need_update or researcher_email_index < 0 or researcher_name_index < 0:
                self.debuglog_r(
                    "--- Correct Salesforce link [{sf_case_num}|{link}]".format(
                        sf_case_num=sf_case_num, link=link
                    )
                )
                self.debuglog_r(
                    "---         Case Number: {sf_case_num}, Researcher: {researcher_name} [{researcher_email}]".format(
                        sf_case_num=sf_case_num,
                        researcher_name=researcher_name,
                        researcher_email=researcher_email,
                    )
                )
                self.issue.update(
                    description="[{sf_case_num}|{link}]\n[vauthor][{researcher_name}] [{researcher_email}]\n[sf-subject] {sf_subject}\n\n{others}".format(
                        sf_case_num=sf_case_num,
                        link=link,
                        researcher_name=researcher_name,
                        researcher_email=researcher_email,
                        sf_subject=summary,
                        others=others,
                    )
                )
        ### Update label SF case num
        if sf_case_num and not self.does_label_exist("SF:" + sf_case_num):
            self.update_labels("SF:" + sf_case_num)

        ### Add 'vulnerability_report' in components
        self.add_component("vulnerability_report")

        ### Update date
        self.sf_created_date, sf_created_date_str = self.get_time_n_str(
            created_date, s_format=s_format, local_tz_str=local_tz_str
        )

    def code_review_announcement(self, model, assignee):
        if (
            model
            in [
                "qts",
                "quts hero",
                "qutscloud",
                "qpkg",
                "qne",
                "qvp",
                "qvr",
                "qes",
                "main",
            ]
            or self.issue.fields.summary.find("Mantis#")
        ) and self.issue.fields.summary.find("(3rd-party)") <= 0:
            claim = (
                "h3. *{color:#de350b}依據公司政策，所有 V3 (含) 等級以上的資安 bug 單，RD 在正式進 code 前，除了各單位內部的 code review 機制，需要額外指派資安 reviewer 協助做 security code review：{color}*\n"
                "h3. {color:#de350b}1. 方法可以參考此文件 [CodeReview流程與稽核|https://ieinet.sharepoint.com/:p:/r/sites/msteams_7625dd/Shared%20Documents/BSIMM/%E9%A0%90%E9%98%B2%E5%B7%A5%E4%BD%9C/CodeReview/CodeReview%E6%B5%81%E7%A8%8B%E8%88%87%E7%A8%BD%E6%A0%B8.pptx?d=w86909161a88d4f6380595bfc4a5aa066&csf=1&web=1&e=3ybLWv]{color}\n"
                "h3. {color:#de350b}2. 請先完成單位內部的 code review，再指派給資安 reviewer 進行 security code review{color}\n"
                "h3. {color:#de350b}3. 如需參與 QTS code review 審查會議，請先完成 security code review{color}\n"
                "h3. {color:#de350b}4. 此資安 bug 單的資安 reviewer 為軟體架構部 {color}"
            )
            self.issue.update(
                description="{claim}{{color:#0b35de}}{assignee}{{color}}\n\n{origin}".format(
                    claim=claim, assignee=assignee, origin=self.issue.fields.description
                )
            )

    def rotate_assign_analyst(self, model, data, downloads):
        if (
            "StanleySHuang@qnap.com".lower()
            == self.issue.raw["fields"]["assignee"]["name"].lower()
        ):
            from pkg._fdb.vulnrep_global_config import vglobalconfig

            global_config = vglobalconfig(data, downloads)
            if "researcher_email" in self.sf_data and self.sf_data["researcher_email"]:
                self.debuglog_r(
                    "    researcher: {researcher}".format(
                        researcher=self.sf_data["researcher_email"]
                    )
                )
                assignee = global_config.select_analyst(
                    model, email=self.sf_data["researcher_email"]
                )
            else:
                self.debuglog_r("    researcher: --unknown--")
                assignee = global_config.select_analyst(model)
            comments = self.issue.fields.comment.comments
            if (
                len(comments) == 0
                or comments[len(comments) - 1].body.find(assignee) < 0
            ):
                if model == "main":
                    self.jira.add_comment(
                        self.issue,
                        "[~{assignee}],\n此報告含多份弱點報告，請協助拆單與分析。\n如果研究員對各別報告有命名或編號，請在子 Jira 單 Description 中下 '[sf-sub-report] + /* 研究員對各別報告的命名或編號 */' 標籤識別，感謝！".format(
                            assignee=assignee
                        ),
                    )
                else:
                    self.jira.add_comment(
                        self.issue,
                        "[~{assignee}],\n請協助此弱點分析，謝謝。".format(
                            assignee=assignee
                        ),
                    )
                self.code_review_announcement(model, assignee)
            return assignee
        return None

    def set_status(self, data, downloads):
        ### determine resolution time, V3 90 days, V4/V5 60 days
        resolution_days = 60
        severity_level = 0
        if self.analysis and self.analysis.is_analysis_done():
            severity_level = self.analysis.get_severity_level()
            # print('severity_level == ' + severity_level)
            if severity_level and content_filter(
                severity_level, ["[V3]", "[V2]"], b_op_and=False
            ):
                resolution_days = 90
            elif severity_level and content_filter(
                severity_level, ["[V4]", "[V5]"], b_op_and=False
            ):
                resolution_days = 30
        # print('--- resolution_days == ' + str(resolution_days))
        if self.sf_created_date:
            deadline = pick_n_days_after(self.sf_created_date, resolution_days)
            deadline_str = utc_to_local_str(deadline, format="%Y-%m-%d")
            # print('--- sf_created_date == ' + str(self.sf_created_date))
            # print('--- deadline_str == ' + deadline_str)
            # Vulnerability Reporting Date: customfield_16400
            # Release Deadline:             customfield_16401
            # Finish ETA:                   customfield_11504
            # if Release Deadline is None or earlier than deadline, then update
            if (
                self.issue.key.find("INTSI000") >= 0
                and self.issue.raw["fields"]["customfield_16401"]
            ):
                original_deadline = datetime.strptime(
                    self.issue.raw["fields"]["customfield_16401"], "%Y-%m-%d"
                )
                original_deadline_str = self.issue.raw["fields"]["customfield_16401"]
            else:
                original_deadline = datetime.now()
                original_deadline_str = utc_to_local_str(
                    original_deadline, format="%Y-%m-%d"
                )

            sf_created_date_str = utc_to_local_str(
                self.sf_created_date, format="%Y-%m-%d"
            )
            if (
                self.issue.key.find("INTSI000") >= 0
                and self.issue.raw["fields"]["customfield_16400"] != sf_created_date_str
            ):
                # 更新 SF 開單日
                self.issue.update(fields={"customfield_16400": sf_created_date_str})
                self.debuglog_r(
                    "--- Update Vulnerability Reporting Date  {sf_created_date_str}".format(
                        sf_created_date_str=sf_created_date_str
                    )
                )

            # 有時這個欄位一開始是 None (尤其是由同事開單時)
            if (
                self.issue.key.find("INTSI000") >= 0
                and self.issue.raw["fields"]["customfield_16401"] is None
            ):
                self.issue.update(fields={"customfield_16401": original_deadline_str})
            if deadline > original_deadline or (
                deadline != original_deadline
                and severity_level
                and content_filter(severity_level, ["[V5]"], b_op_and=False)
            ):
                self.debuglog_r(
                    "--- Original Deadline                    " + original_deadline_str
                )
                if (
                    self.issue.key.find("INTSI000") >= 0
                    and self.issue.raw["fields"]["customfield_16401"] != deadline_str
                ):
                    # 更新 deadline
                    self.issue.update(fields={"customfield_16401": deadline_str})
                    self.debuglog_r(
                        "--- Update Release Deadline              {deadline_str}".format(
                            deadline_str=deadline_str
                        )
                    )
                if self.issue.raw["fields"]["customfield_11504"] != deadline_str:
                    # 更新 ETA
                    self.issue.update(fields={"customfield_11504": deadline_str})
                    self.debuglog_r(
                        "--- Update Finish ETA                    {deadline_str}".format(
                            deadline_str=deadline_str
                        )
                    )
        ### assignee
        if (
            "StanleySHuang@qnap.com".lower()
            == self.issue.raw["fields"]["assignee"]["name"].lower()
            and "To Do" == self.issue.fields.status.name
        ):
            # transitions = self.jira.transitions(self.issue)
            # print([(t['id'], t['name']) for t in transitions]) # [('51', 'abort'), ('11', 'handling ')]
            try:
                self.jira.transition_issue(self.issue, "11")
                self.debuglog_r("--- Update Status                        In Progress")

                model, product, ver = extract_model(self.issue.fields.summary)
                from pkg._fdb.vulnrep_global_config import vglobalconfig

                global_config = vglobalconfig(data, downloads)
                if model == "qnap cloud service":
                    assignee = "AnryLu@qnap.com"
                    analysis_task.add_watchers(
                        self.jira, self.issue, ["HarryChen@qnap.com"]
                    )
                    self.jira.add_comment(
                        self.issue,
                        "[~{assignee}],\n請協助檢查此弱點報告是否重複，謝謝。".format(
                            assignee=assignee
                        ),
                    )
                elif model == "amiz cloud":
                    assignee = "HarryChen@qnap.com"
                    analysis_task.add_watchers(
                        self.jira, self.issue, ["AnryLu@qnap.com"]
                    )
                    self.jira.add_comment(
                        self.issue,
                        "[~{assignee}],\n請協助檢查此弱點報告是否重複，謝謝。".format(
                            assignee=assignee
                        ),
                    )
                elif model == "quwan":
                    assignee = "JocephWang@qnap.com"
                    analysis_task.add_watchers(
                        self.jira, self.issue, ["AnryLu@qnap.com", "HarryChen@qnap.com"]
                    )
                    self.jira.add_comment(
                        self.issue,
                        "[~{assignee}],\n請協助檢查此弱點報告以前有沒有研究員報告過？需不需要修復？然後再轉回給 Stanley，謝謝。".format(
                            assignee=assignee
                        ),
                    )
                elif model == "qnap website":
                    assignee = "KyleChao@qnap.com"
                    self.jira.add_comment(
                        self.issue,
                        "[~{assignee}],\n請協調相關當責單位進行弱點報告分析與修復，謝謝。".format(
                            assignee=assignee
                        ),
                    )
                elif model == "iei website":
                    assignee = "AlexChien@ieiworld.com"
                    self.jira.add_comment(
                        self.issue,
                        "[~{assignee}],\n請協調相關當責單位進行弱點報告分析與修復，謝謝。".format(
                            assignee=assignee
                        ),
                    )
                elif self.issue.fields.summary.lower().find("samba") >= 0:
                    assignee = "JonesSyue@qnap.com"
                    analysis_task.add_watchers(
                        self.jira, self.issue, ["SharonHsiao@qnap.com"]
                    )
                    self.jira.add_comment(
                        self.issue,
                        "[~{assignee}],\n請協助此弱點分析，並建議修復與驗證方法，謝謝。".format(
                            assignee=assignee
                        ),
                    )
                elif self.assignee is None:
                    assignee = self.rotate_assign_analyst(model, data, downloads)
                else:
                    assignee = self.assignee
                    self.code_review_announcement(model, assignee)

                    if self.issue.fields.summary.find('[main]') >= 0:
                        self.jira.add_comment(
                            self.issue,
                            "[~{assignee}],\n此報告含多份弱點報告，請協助拆單與分析。\n如果研究員對各別報告有命名或編號，請在子 Jira 單 Description 中下 '[sf-sub-report] + /* 研究員對各別報告的命名或編號 */' 標籤識別，感謝！".format(
                                assignee=assignee
                            ),
                        )
                    else:
                        self.jira.add_comment(
                            self.issue,
                            "[~{assignee}],\n請協助此弱點分析，謝謝。".format(
                                assignee=assignee
                            ),
                        )

                self.issue.update(assignee={"name": assignee})

                weight = 1.0
                model, product, ver = extract_model(self.issue.fields.summary)
                if model in [
                    "qnap cloud service",
                    "amiz cloud",
                    "qnap website",
                    "iei website",
                ]:
                    weight = 0.2
                elif self.issue.fields.summary.lower().find("samba") >= 0:
                    weight = 1.0
                global_config.assign_analyst(assignee, weight=weight)
                self.debuglog_r(
                    "--- Update Assignee                      {assignee}".format(
                        assignee=assignee
                    )
                )
            except Exception as e:
                print("    " + str(e))

        # PgM Project Update: customfield_13601
        # str_customfield_13601 = ""  # self.debug_obj.output_buff
        # if self.issue.raw["fields"]["customfield_13601"] != str_customfield_13601:
            # print('--- Update Status (customfield_13601): [{data}]'.format(data=self.issue.raw['fields']["customfield_13601"]))
            # self.issue.update(fields={"customfield_13601": str_customfield_13601})

    def get_gsheet_raw(self):
        """
        raw = {
            "researcher_email":,
            'sf_created':,
            'sf_case_num':,
            ### Analysis
            'triaged':,
            'triaged_duration':,
            'validated':,
            'severity_level':,
            'cveid':,
            'summary':,
            'sf-sub-report':,
            ### Resolvation
            'fixing':,
            'resolved':,
            'verified':,
            'resolved_duration':,
            'verified_duration':,
            'bug_num':,
            'not_affected_num':,
            'at_verified_num':,
            'at_resolved_num':,
            ### Release
            'labtest':,
            'release':,
            'release_duration':,
            'overall_duration':,
            'at_released_num':,
            'at_labtest_num':,
            'done':,
            'dependency_resolved':,
            'one_resolved':,
            'all_fixed':,
            'one_fixed':,
            'triage_done':,
            'cve_json_url':,
        }
        """
        now = datetime.now()
        ### Salesforce Data
        raw = {
            "researcher_email": None,
            "sf_created": None,
            "sf_case_num": None,
        }
        if "researcher_email" in self.sf_data:
            raw["researcher_email"] = self.sf_data["researcher_email"]
            raw["sf_created"] = self.sf_data["created_date"]
            raw["sf_case_num"] = self.sf_data["sf_case_num"]
        ### Analysis
        if self.analysis:
            raw = self.analysis.set_raw(raw)
            raw["key"] = self.issue.key
            raw["summary"] = self.issue.fields.summary
            raw["sf-sub-report"] = self.extract_sf_subject()
        ### Resolvation
        if self.fixing_date:
            fixing_date, raw["fixing"] = self.get_time_n_str(self.fixing_date)
        else:
            raw["fixing"] = "N/A"
        if self.resolved_date:
            resolved_date, raw["resolved"] = self.get_time_n_str(self.resolved_date)
        else:
            raw["resolved"] = "N/A"
        if self.verified_date:
            verified_date, raw["verified"] = self.get_time_n_str(self.verified_date)
        else:
            raw["verified"] = "N/A"
        if self.fixing_date and self.resolved_date and self.resolved_date != "N/A":
            raw["resolved_duration"] = duration_days(fixing_date, resolved_date)
        elif self.fixing_date:
            raw["resolved_duration"] = duration_days(fixing_date, now)
        else:
            raw["resolved_duration"] = "N/A"
        if self.resolved_date and self.verified_date and self.verified_date != "N/A":
            raw["verified_duration"] = duration_days(resolved_date, verified_date)
        elif self.resolved_date:
            raw["verified_duration"] = duration_days(resolved_date, now)
        else:
            raw["verified_duration"] = "N/A"
        raw["bug_num"] = str(self.bug_num)
        raw["not_affected_num"] = str(self.not_affected_num)
        raw["at_verified_num"] = str(self.verified_num)
        raw["at_resolved_num"] = str(self.resolved_num - self.verified_num)

        ### Release
        if self.labtest_date and self.labtest_date != "N/A":
            labtest_date, raw["labtest"] = self.get_time_n_str(
                self.labtest_date, s_format="%Y-%m-%d"
            )
        else:
            raw["labtest"] = "N/A"
        if self.release_date and self.release_date != "N/A":
            release_date, raw["release"] = self.get_time_n_str(
                self.release_date, s_format="%Y-%m-%d"
            )
        else:
            raw["release"] = "N/A"
        if (
            self.labtest_date
            and self.release_date
            and self.labtest_date != "N/A"
            and self.release_date != "N/A"
        ):
            raw["release_duration"] = duration_days(labtest_date, release_date)
        elif self.labtest_date and self.labtest_date != "N/A":
            raw["release_duration"] = duration_days(labtest_date, now)
        else:
            raw["release_duration"] = "N/A"

        if self.sf_created_date:
            created_date = self.sf_created_date
        else:
            s_format = "%Y-%m-%dT%H:%M:%S.000+0800"
            local_tz_str = "Asia/Taipei"
            created_date, created_date_str = self.get_time_n_str(
                self.issue.fields.created, s_format=s_format, local_tz_str=local_tz_str
            )

        if self._closed_date:
            raw["overall_duration"] = duration_days(created_date, self._closed_date)
        else:
            if self.release_date and self.release_date != "N/A":
                raw["overall_duration"] = duration_days(created_date, release_date)
            else:
                raw["overall_duration"] = duration_days(created_date, now)
        raw["at_released_num"] = str(self.released_num)
        raw["at_labtest_num"] = str(self.labtest_num - self.released_num)
        if self.b_resolved:
            raw["done"] = "Yes"
        else:
            raw["done"] = "No"
        if self.b_dependency_resolved and self.analysis.is_done():
            raw["dependency_resolved"] = "Yes"
        else:
            raw["dependency_resolved"] = "No"
        if self._b_all_fixed and (self.is_main_task() or self.analysis.is_done()):
            raw["all_fixed"] = "Yes"
        else:
            raw["all_fixed"] = "No"
        if self._b_one_fixed and (self.is_main_task() or self.analysis.is_done()):
            raw["one_fixed"] = "Yes"
        else:
            raw["one_fixed"] = "No"
        if self.analysis.is_done():
            raw["triage_done"] = "Yes"
        else:
            raw["triage_done"] = "No"
        if self._cve_json_url and len(self._cve_json_url) > 0:
            raw["cve_json_url"] = self._cve_json_url
        return raw

    def is_main_task(self):
        model, product, ver = extract_model(self.issue.fields.summary)
        if model == "main":
            return True
        return False

    def trace_dependency(self):
        from .bug import vuln_bug

        if self.b_dependency_traced:
            return

        self.b_dependency_traced = True
        self.dependent_counts = 0
        self.dependent_issues = []

        if self.is_main_task():
            self.search_blocked()
            for blocked_issue in self.blocked_issues:
                if get_issuetype(blocked_issue) == "Task":
                    blocked_task = analysis_task(
                        self.jira, blocked_issue, self.debug_obj
                    )
                    self.dependent_counts += 1
                    self.dependent_issues.append(blocked_task)
                    blocked_task.set_sf_data(
                        self.sf_data["created_date"] + "T00:00:00.000+0000",
                        self.sf_data["researcher_email"],
                        self.sf_data["researcher_name"],
                        self.sf_data,
                    )
        else:
            self.search_blocked()
            self.search_blocking()
            for blocked_issue in self.blocked_issues:
                if get_issuetype(blocked_issue) == "Bug":
                    the_bug = vuln_bug(self.jira, blocked_issue, self.debug_obj)
                    self.dependent_counts += 1
                    self.dependent_issues.append(the_bug)
            for blocking_issue in self.blocking_issues:
                if get_issuetype(blocking_issue) == "Bug":
                    the_bug = vuln_bug(self.jira, blocking_issue, self.debug_obj)
                    self.dependent_counts += 1
                    self.dependent_issues.append(the_bug)

    def set_closed_date(self, data, downloads):
        # the_task_closed_date
        the_task_closed_date = None
        if self.get_status_name() in ["close"]:
            (
                closer,
                str_closed_detailed_date,
                status,
            ) = self.get_auther_and_created_in_changlog("status", ["close"])
            closed_date, str_closed_date = self.get_time_n_str(str_closed_detailed_date)
            the_task_closed_date = closed_date
        elif self.get_status_name() in ["abort"]:
            (
                aborter,
                str_abort_detailed_date,
                status,
            ) = self.get_auther_and_created_in_changlog("status", ["abort"])
            abort_date, str_abort_date = self.get_time_n_str(str_abort_detailed_date)
            the_task_closed_date = abort_date

        if the_task_closed_date:
            self._closed_date = the_task_closed_date
        return self._closed_date

    def triage_view(self, data, downloads, b_update):
        """
        analysis_obj:   {
                            'b_done':           analysis done or not 與 label 'triaged' 同步
                            'created':          date time in format '2021-05-13',
                            'validated':        date time in format '2021-05-13',
                            'duration':         the duration between created to done,
                            'cweids':           CWD ID array,
                            'cvssv3_vec':       CVSS vector,
                            'cvssv3_score':     CVSS score,
                            'severity_level':   severity level,
                            'cveid':            CVE ID,
                        }
        """
        ### 建立 analysis 物件
        if self.analysis is None:
            self.analysis = analysis(data, downloads)
        self.analysis.load(self.issue.key)

        ### label triaged 相當於 analysis b_done 為 True
        if self.does_label_exist("triaged"):
            return

        ### 設定 analysis 開始時間，與花費時間。
        the_task_created_date, str_the_task_created_date = self.get_created_n_str()
        now = datetime.now()
        self.analysis.init(the_task_created_date, now)
        """
        if self.get_status_name() in ['close']:
            self.analysis.task_done(self._closed_date)
        """

        ### 更新 analysis b_done, labels: 'triaged'
        if self.is_main_task():
            # 檢查子任務是否已完成分析
            b_all_blocked_tasks_done = True
            validated_date = None
            for blocked_task in self.dependent_issues:
                # print("分析子任務：" + blocked_task.issue.key)
                if blocked_task.analysis is None:
                    blocked_task.analysis = analysis(data, downloads)
                blocked_task.analysis.load(blocked_task.issue.key)
                if not blocked_task.does_label_exist("triaged"):
                    # print("    " + blocked_task.issue.key + " is not triaged.")
                    b_all_blocked_tasks_done = False
                else:
                    blocked_task_validated_date = blocked_task.analysis.get_validated()
                    # 如果新的更新日期，比原來紀錄還新，更新花費時間
                    if (
                        validated_date is None
                        or blocked_task_validated_date > validated_date
                    ):
                        validated_date = blocked_task_validated_date

            # 如果子任務都完成，主任務也等於完成。
            if b_update and b_all_blocked_tasks_done and len(self.dependent_issues) > 0:
                if validated_date is None:
                    validated_date = datetime.now()
                self.analysis.set_validated(validated_date)
                self.analysis.analysis_done()
                self.update_labels("triaged")
                # print("    " + self.issue.key + " is triaged.")

        if not self.is_main_task() or (
            self.issue.fields.summary.lower().find("[security]") >= 0
            and self.issue.fields.summary.lower().find("cve-") >= 0
        ):
            ### 找 severity level
            b_summary_with_severity = self.analysis.update_cveid_severity_summary(
                self.issue.fields.summary,
                self.issue.changelog.histories,
                self.issue.fields.reporter.name,
                str_the_task_created_date,
                sf_sub_report = self.extract_sf_subject()
            )
            if b_summary_with_severity:
                comments = self.issue.fields.comment.comments
                for comment in comments:
                    if not self.analysis.if_cwe_capec_cvss_exist():
                        comment_parser(
                            self.analysis,
                            comment,
                            [
                                [
                                    "CVSS",
                                    "CWE-",
                                    "CAPEC-",
                                    "- CAPEC ID(s)",
                                    "Description",
                                    "POC",
                                    "Steps",
                                    "Content",
                                ]
                            ],
                            analysis.cve_json_callback,
                        )

                # 如果 comments 沒有資訊，且 reporter 不是 bot 搜尋 description
                if not self.analysis.if_cwe_capec_cvss_exist():
                    reporter = self.issue.fields.reporter.name
                    if reporter != "PSIRT_Jira_Robot":
                        description = self.issue.fields.description
                        description_parser(
                            self.analysis,
                            description,
                            self.issue.fields.created,
                            [
                                [
                                    "CVSS",
                                    "CWE-",
                                    "CAPEC-",
                                    "- CAPEC ID(s)",
                                    "Description",
                                    "POC",
                                    "Steps",
                                    "Content",
                                ]
                            ],
                            analysis.cve_json_callback,
                        )
                ### if cwe, capec, cvssv3 not available, request data
                if not self.analysis.if_cwe_capec_cvss_exist():
                    request_info_msg = self.analysis.request_info_msg(
                        self.issue.fields.summary
                    )
                    if request_info_msg:
                        author = self.analysis.json_obj["author"]
                        self.debuglog_r(
                            "   triage request {author} more data - post {request_info_msg}".format(
                                author=author,
                                request_info_msg=request_info_msg.replace("\n", " "),
                            )
                        )
                        """
                        if author.lower()!=self.issue.fields.assignee.name.lower():
                            self.issue.update(assignee={'name': author})
                        """
                        if (
                            len(comments) == 0
                            or comments[len(comments) - 1].body.find(request_info_msg)
                            < 0
                        ):  # 檢查最後一則 po 文是否為相同訊息。
                            self.jira.add_comment(self.issue, request_info_msg)
                        self.analysis.flush(self.issue.key)
                        return  # Triage 未完成
                if b_update:
                    self.analysis.analysis_done()
                    self.update_labels("triaged")

        self.analysis.flush(self.issue.key)

    def run(self, root_issue, parent_issue, data, downloads, b_update=False):
        self.debuglog_r(
            "--> [Task-{key}] - {summary}".format(
                key=self.issue.key, summary=self.issue.fields.summary
            )
        )
        the_task_closed_date = self.set_closed_date(data, downloads)
        self.trace_dependency()

        ### Triage
        if self.is_main_task():
            for blocked_issue in self.dependent_issues:
                if get_issuetype(blocked_issue.issue) == "Task":
                    blocked_issue.triage_view(data, downloads, b_update)
        self.triage_view(data, downloads, b_update)

        ### Set Status
        bug_raws = []
        release_raws = []
        if self.is_main_task():
            self.b_dependency_resolved = True
            self._b_all_fixed = True
            self._b_one_fixed = False
            for blocked_issue in self.dependent_issues:
                if get_issuetype(blocked_issue.issue) == "Task":
                    (
                        blocked_issue_raw,
                        blocked_issue_bug_raws,
                        blocked_issue_release_raws,
                    ) = blocked_issue.run(root_issue, self, data, downloads, b_update)
                    bug_raws.extend(blocked_issue_bug_raws)
                    release_raws.extend(blocked_issue_release_raws)
                    if (
                        blocked_issue_raw["all_fixed"] == "No"
                        or not blocked_issue.analysis.is_done()
                    ):
                        self._b_all_fixed = False
                    if blocked_issue_raw["one_fixed"] == "Yes":
                        self._b_one_fixed = True
                    if "at_resolved_num" in blocked_issue_raw:
                        self.resolved_num += int(blocked_issue_raw["at_resolved_num"])
                    if "at_verified_num" in blocked_issue_raw:
                        self.verified_num += int(blocked_issue_raw["at_verified_num"])
                    if "at_labtest_num" in blocked_issue_raw:
                        self.labtest_num += int(blocked_issue_raw["at_labtest_num"])
                    if "at_released_num" in blocked_issue_raw:
                        self.released_num += int(blocked_issue_raw["at_released_num"])
                    if "bug_num" in blocked_issue_raw:
                        self.bug_num += int(blocked_issue_raw["bug_num"])
                    if "not_affected_num" in blocked_issue_raw:
                        self.not_affected_num += int(
                            blocked_issue_raw["not_affected_num"]
                        )

                    ### 在這裡搜集子單的 _raw data
                    if b_update:
                        blocked_issue.set_status(data, downloads)
            self.resolved_num += self.verified_num
            self.labtest_num += self.released_num
        else:
            bug_created = []
            bug_resolved = []
            bug_verified = []
            labtest_dates = []
            release_dates = []
            self.b_dependency_resolved = True
            self._b_all_fixed = True
            self._b_one_fixed = False
            # self.b_resolved
            # self.bug_num
            # self.not_affected_num
            # self.resolved_num
            # self.verified_num
            # self.labtest_num
            # self.released_num
            # self.fixing_date
            # self.resolved_date
            # self.verified_date
            # self.labtest_date
            # self.release_date

            for issue in self.dependent_issues:
                if get_issuetype(issue.issue) == "Bug":
                    bug_raw, children = issue.run(
                        root_issue, self, data, downloads, b_update
                    )
                    bug_raws.append(bug_raw)
                    release_raws.extend(children)
                    the_bug = issue
                    if the_bug._b_fix_status == "fixed":
                        self._b_one_fixed = True
                    elif the_bug._b_fix_status == "not_fixed":
                        self._b_all_fixed = False
                        self.b_dependency_resolved = False
                        model, product, ver = extract_model(
                            the_bug.issue.fields.summary
                        )
                        self.debuglog_r(
                            "    UNRESOLVE [BUG-{key}] - [{product}], in status: {status}".format(
                                key=the_bug.issue.key,
                                product=product,
                                status=the_bug.get_status_name(),
                            )
                        )
                    else:
                        # the_bug._b_fix_status == 'not_affected'
                        self.not_affected_num += 1

                    bug_created.append(the_bug.issue.fields.created)
                    rd, resolved, status = the_bug.get_auther_and_created_in_changlog(
                        "status", ["resolved"]
                    )
                    dqv, verified, status = the_bug.get_auther_and_created_in_changlog(
                        "status", ["verified"]
                    )
                    if rd and resolved and the_bug._b_fix_status != "not_affected":
                        bug_resolved.append(resolved)
                    if dqv and verified and the_bug._b_fix_status == "fixed":
                        bug_verified.append(verified)
                    if the_bug.labtest_date:
                        labtest_dates.append(the_bug.labtest_date)
                    if the_bug.release_date:
                        release_dates.append(the_bug.release_date)
                    if b_update and self.does_component_exist("vulnerability_report"):
                        the_bug.add_component("vulnerability_report")

            # fixing_date: bug created date
            bug_created = sorted(bug_created)
            self.bug_num = len(bug_created)
            if len(bug_created) > 0:
                self.fixing_date = bug_created[0]
            # resolved_date: bug resolved date
            if len(bug_resolved) > 0 and len(bug_resolved) >= (
                self.bug_num - self.not_affected_num
            ):
                bug_resolved = sorted(bug_resolved)
                self.resolved_date = bug_resolved[len(bug_resolved) - 1]
                for resolved_date in reversed(bug_resolved):
                    if resolved_date != "N/A":
                        self.resolved_date = resolved_date
                        break
            else:
                self.resolved_date = None

            # verified_date: bug verified date
            if len(bug_verified) > 0 and len(bug_verified) >= (
                self.bug_num - self.not_affected_num
            ):
                bug_verified = sorted(bug_verified)
                self.verified_date = bug_verified[len(bug_verified) - 1]
                for verified_date in reversed(bug_verified):
                    if verified_date != "N/A":
                        self.verified_date = verified_date
                        break
            else:
                self.verified_date = None

            # resolved bug num
            self.resolved_num = len(bug_resolved)
            # verified bug num
            self.verified_num = len(bug_verified)

            ### Release
            # lab testing date
            labtest_dates = sorted(labtest_dates)
            if len(labtest_dates) > 0:
                self.labtest_date = labtest_dates[0]
            # release date
            release_dates = sorted(release_dates)
            if (
                len(release_dates) > 0
                and len(release_dates) == len(labtest_dates)
                and len(labtest_dates) >= self.bug_num
            ):
                self.release_date = release_dates[len(release_dates) - 1]
                for release_date in reversed(release_dates):
                    if release_date != "N/A":
                        self.release_date = release_date
                        break
            else:
                self.release_date = None

            # labtest num
            self.labtest_num = len(labtest_dates)
            # release num
            self.released_num = len(release_dates)

            b_legacy_case = False
            b_production_web_verified = False
            b_convert_to_requirement = False
            labels = self.issue.raw["fields"]["labels"]
            for label in labels:
                if label in ["legacy_case"]:
                    b_legacy_case = True
                if label in ["production_web_verified"]:
                    b_production_web_verified = True
                if label in ["convert_to_requirement"]:
                    b_convert_to_requirement = True

            if self.get_status_name() in ["close"] and self.b_dependency_resolved:
                self.b_resolved = True
                self._b_all_fixed = True
                self._b_one_fixed = True
                self.debuglog_r(
                    "*** CLOSE [Task-{key}] - all dependency resolved - [{closed_date}]".format(
                        key=self.issue.key, closed_date=the_task_closed_date
                    )
                )
            elif self.get_status_name() in ["close"] and b_legacy_case:
                self.b_resolved = True
                self._b_all_fixed = True
                self._b_one_fixed = True
                self.debuglog_r(
                    "*** CLOSE [Task-{key}] - legacy issue".format(key=self.issue.key)
                )
            elif self.get_status_name() in ["abort"]:
                self.debuglog_r(
                    "*** CLOSE [Task-{key}] - abort - [{abort_date}]".format(
                        key=self.issue.key, abort_date=the_task_closed_date
                    )
                )
                self.b_resolved = True
                self._b_all_fixed = True
                self._b_one_fixed = True
            elif b_production_web_verified:
                self.b_resolved = True
                self._b_all_fixed = True
                self._b_one_fixed = True
                self.debuglog_r(
                    "*** CLOSE [Task-{key}] - Web Production Verified".format(
                        key=self.issue.key
                    )
                )
            elif b_convert_to_requirement:
                self.b_resolved = True
                self._b_all_fixed = True
                self._b_one_fixed = True
                self.debuglog_r(
                    "*** CLOSE [Task-{key}] - Convert to Requirement".format(
                        key=self.issue.key
                    )
                )
            elif self.analysis.is_done() and self.b_dependency_resolved:
                if any(
                    map(
                        self.issue.fields.summary.lower().__contains__,
                        ["[iei website]", "[qnap website]"],
                    )
                ):
                    # IEI 與 QNAP 官網:
                    if self.get_status_name() in ["confirm / test"]:
                        (
                            dqv,
                            verified_date,
                            status,
                        ) = self.get_auther_and_created_in_changlog(
                            "status", ["confirm / test"]
                        )
                        self.b_resolved = True
                        self._b_all_fixed = True
                        self._b_one_fixed = True
                        self.debuglog_r(
                            "*** CLOSE [Task-{key}] - issue resolved - [{verified_date}]".format(
                                key=self.issue.key, verified_date=verified_date
                            )
                        )
                    else:
                        created, str_created = self.get_created_n_str()
                        model, product, ver = extract_model(self.issue.fields.summary)
                        self.debuglog_r(
                            ">>> fixing [Task-{key}] - [{product}]".format(
                                key=self.issue.key, product=product
                            ),
                            since=created,
                        )
                else:
                    model, product, ver = extract_model(self.issue.fields.summary)
                    if self.bug_num == 0 and self.get_status_name() not in [
                        "close",
                        "abort",
                        "confirm / test",
                    ]:
                        created, str_created = self.get_created_n_str()
                        self.debuglog_r(
                            ">>> fixing [Task-{key}] - [{product}]".format(
                                key=self.issue.key, product=product
                            ),
                            since=created,
                        )
                        self.b_resolved = False
                    else:
                        self.debuglog_r(
                            ">>> close [Task-{key}] - [{product}], all dependency resolved - consider close the case".format(
                                key=self.issue.key, product=product
                            )
                        )
            else:
                if not self.analysis.is_done():
                    created, str_created = self.get_created_n_str()
                    self.debuglog_r(
                        ">>> triage [Task-{key}]".format(key=self.issue.key),
                        since=created,
                    )
                self.b_resolved = False

        ### update Status Update
        return self.get_gsheet_raw(), bug_raws, release_raws

    def check(self, root_issue, parent_issue, data, downloads, b_update=False):
        raw, bug_raws, release_raws = self.run(
            root_issue, parent_issue, data, downloads, b_update=b_update
        )
        if b_update:
            self.set_status(data, downloads)
        return raw, bug_raws, release_raws

    def reward_view(self, root_issue, parent_issue, data, downloads, b_update=False):
        """
        reward = {
            'sf_num': Salesforce Number
            'issue_key': jira key
            'created_date': SF 開單日
            'summary': 一定有值,
            'severity_level': 有值表示分析階段完成,
            'cveid': 有值表示需要公布,
            'one_fixed': 有值表示至少一個平台已解,
            'reward_draft': 有值表示已建議獎金（但為效能，後續批次處理）
            'description_score': 報告品質
            'poc_score': 報告品質
            # 'suggestion_score': 報告品質
        }
        """
        raw, bug_raws, release_raws = self.run(
            root_issue, parent_issue, data, downloads, b_update=b_update
        )
        summary = self.issue.fields.summary.replace(
            "[SF:" + raw["sf_case_num"] + "]", ""
        )
        reward = {
            "sf_num": raw["sf_case_num"],
            "issue_key": "{issue_key}".format(issue_key=self.issue.key),
            "created_date": "{created_date}".format(created_date=raw["sf_created"]),
            "summary": "{created_date}: [{sf_case_num}][{issue_key}]{issue_summary}".format(
                created_date=raw["sf_created"],
                sf_case_num=raw["sf_case_num"],
                issue_summary=summary,
                issue_key=self.issue.key,
            ),
        }
        if (
            "severity_level" in raw
            and raw["severity_level"] is not None
            and len(raw["severity_level"]) > 0
        ):
            reward["severity_level"] = raw["severity_level"]
        if "cveid" in raw and raw["cveid"] is not None and len(raw["cveid"]) > 0:
            reward["cveid"] = raw["cveid"]
        if "one_fixed" in raw and raw["one_fixed"] == "Yes":
            reward["one_fixed"] = True
        if (
            "description_score" in raw
            and raw["description_score"] is not None
            and raw["description_score"] > 0
        ):
            reward["description_score"] = raw["description_score"]
        if "poc_score" in raw and raw["poc_score"] is not None and raw["poc_score"] > 0:
            reward["poc_score"] = raw["poc_score"]
        """
        if 'suggestion_score' in raw and raw['suggestion_score'] is not None and raw['suggestion_score']>0:
            reward['suggestion_score'] = raw['suggestion_score']
        """
        return reward

    def find_task(self):
        return self.issue

    def set_assignee(self, assignee):
        self.assignee = assignee

    def make_finding_response(self, vfinding_response, vbountyhunter, data, downloads):
        if self.is_main_task():
            b_one_analysis_done = False
            sub_tasks = []
            rejecteds = []
            for blocked_issue in self.dependent_issues:
                if get_issuetype(blocked_issue.issue) == "Task":
                    blocked_task = blocked_issue
                    if blocked_task.analysis.is_analysis_done():
                        ### report valid and analysis done
                        b_one_analysis_done = True
                        if vfinding_response.is_existing(blocked_task.issue.key):
                            the_summary = "n/a"
                            cveids = extract_cveid(blocked_task.issue.fields.summary)
                            if cveids:
                                the_summary = ", ".join(cveids)
                            sub_task = {
                                "summary": the_summary,
                                "validated": blocked_task.analysis.json_obj[
                                    "validated"
                                ],
                                "analysis": blocked_task.analysis,
                            }
                            """ an example
                            issuekey: 'INTSI000-4687', 
                            sf_data: {
                                'sf_case_num': 'Q-202305-12568', 
                                'sf_case_id': '5002s00000XaJlCAAV', 
                                'researcher_email': 'zhaorunzi0@gmail.com', 
                                'researcher_name': 'runzi zhao', 
                                'created_date': '2023-05-09', 
                                'deadline': '2023-07-08', 
                                'subject': '[SF:Q-202305-12568]  some vulns', 
                                'description': '[Q-202305-12568|https://qnap.lightning.force.com/lightning/r/Case/5002s00000XaJlCAAV/view]\nhttps://qnap-jira.qnap.com.tw/browse/INTSI000-4683\n\nsome vulns, see the zip file.', 
                                'status': 'In Progress', 
                                'sf_link': 'https://qnap.lightning.force.com/lightning/r/Case/5002s00000XaJlCAAV/view'
                            }
                            sf_subject: '[Windows Utility:QVPN Device Client][Security][Medium][V3] Insufficiently Protected Credentials in qvpn.sqlite',
                            b_plan_2_disclose: False, 
                            b_request_info: False, 
                            researcher_name: 'Runzi Zhao', 
                            sub_task: [{
                                'summary': '[Windows Utility:QVPN Device Client][Security][Medium][V3] Insufficiently Protected Credentials in qvpn.sqlite - CVE-2023-23370', 
                                'validated': '2023-05-16', 
                                'analysis': <pkg._fdb.analysis.analysis object at 0x7fcf3b481030>
                            }] """
                            sub_tasks.append(sub_task)
                            # print("summary: " + sub_task["summary"])
                            # print("validated: " + sub_task["validated"])
                            # print(sub_task["analysis"].dump())
                    elif blocked_task.get_status_name() in ["abort"]:
                        the_issue = blocked_task
                        comments = the_issue.issue.fields.comment.comments
                        for comment in comments:
                            content = comment.body
                            if content.find("[gpt-invalid]") >= 0:
                                rejecteds.append(content)
                                break

            if b_one_analysis_done and len(self.sf_data["researcher_email"]) > 0:
                if vfinding_response.need_to_be_modified(
                    self.issue.key, len(sub_tasks)
                ):
                    (
                        b_plan_2_disclose,
                        b_request_info,
                        researcher_name,
                    ) = vbountyhunter.request_researcher_name(
                        self.sf_data["researcher_email"],
                        self.sf_data["researcher_name"],
                    )
                    the_mail_content = vfinding_response.create(
                        self.issue.key,
                        self.sf_data,
                        self.issue.fields.summary,
                        self.issue.fields.description,
                        self.extract_sf_subject(),
                        b_plan_2_disclose,
                        b_request_info,
                        researcher_name,
                        sub_tasks,
                        rejecteds,
                    )
                    if the_mail_content:
                        self.get_investigation_info(data, downloads)
                        # mb_run_get_text 為 True
                        # mb_finding_response 設值
                    if (
                        the_mail_content
                        and self.mb_run_get_text
                        and not self.mb_finding_response
                    ):
                        the_comment = "[gpt_finding_response]\n{noformat}\n"
                        the_comment += json.dumps(the_mail_content, indent=2)
                        the_comment += "\n{noformat}\n"
                        print("    " + the_comment)
                        self.jira.add_comment(self.issue, the_comment)
        else:
            if (
                self.analysis.is_analysis_done()
                and "researcher_email" in self.sf_data
                and len(self.sf_data["researcher_email"]) > 0
            ):
                if vfinding_response.need_to_be_modified(self.issue.key, 1):
                    task_created_date, str_task_created_date = self.get_created_n_str()
                    self.analysis.update_cveid_severity_summary(
                        self.issue.fields.summary,
                        self.issue.changelog.histories,
                        self.issue.fields.reporter.name,
                        str_task_created_date,
                        sf_sub_report = self.extract_sf_subject()
                    )
                    (
                        b_plan_2_disclose,
                        b_request_info,
                        researcher_name,
                    ) = vbountyhunter.request_researcher_name(
                        self.sf_data["researcher_email"],
                        self.sf_data["researcher_name"],
                    )
                    the_data = {
                        "summary": self.issue.fields.summary,
                        "validated": self.analysis.json_obj["validated"],
                        "analysis": self.analysis,
                    }
                    the_mail_content = vfinding_response.create(
                        self.issue.key,
                        self.sf_data,
                        self.issue.fields.summary,
                        self.issue.fields.description,
                        self.extract_sf_subject(),
                        b_plan_2_disclose,
                        b_request_info,
                        researcher_name,
                        [the_data],
                        None,
                    )
                    if the_mail_content:
                        self.get_investigation_info(data, downloads)
                        # mb_run_get_text 為 True
                        # mb_finding_response 設值
                    if (
                        the_mail_content
                        and self.mb_run_get_text
                        and not self.mb_finding_response
                    ):
                        the_comment = "[gpt_finding_response]\n{noformat}\n"
                        the_comment += json.dumps(the_mail_content, indent=2)
                        the_comment += "\n{noformat}\n"
                        print("    " + the_comment)
                        self.jira.add_comment(self.issue, the_comment)

    @staticmethod
    def is_zip_file(filename):
        if filename.lower().endswith(".zip"):
            return True
        return False

    @staticmethod
    def is_text_info_included(filename):
        if filename.lower().endswith(".txt"):
            return True
        elif filename.lower().endswith(".py"):
            return True
        elif filename.lower().endswith(".pdf"):
            return True
        elif filename.lower().endswith(".docx"):
            return True
        elif filename.lower().endswith(".sh"):
            return True
        elif filename.lower().endswith(".md"):
            return True
        return False

    def make_fed_data(self, fed_data, the_attachments):
        the_text = json.dumps(fed_data) + '\n'
        the_text += json.dumps(the_attachments) + '\n'
        return the_text


    def get_investigation_info(self, data, downloads):
        self.mb_run_get_text = True

        import re

        vauthor = "{!Contact.LastName}"
        fed_data = {}
        the_prompt = None

        summary = self.issue.fields.summary
        description = self.issue.fields.description
        fed_data['summary'] = summary
        fed_data['description'] = description
        lines = description.split("\n")
        for line in lines:
            if line.find("[vauthor]") >= 0:
                m = re.search(r"\[vauthor\].*\[(.*)\].*\[.*\]", line)
                if m and m.group(1):
                    vauthor = m.group(1)
                    break

        fed_data['vauthor'] = vauthor

        comments = self.issue.fields.comment.comments.copy()
        if comments and len(comments) > 0:
            comment = comments[-1]
            author = comment.author.displayName
            content = comment.body
            if author.find("StanleyS Huang") >= 0 and content.find("[gpt_prompt]") >= 0:
                the_prompt = content
                comments.pop()

        fed_data['comments'] = []
        for comment in comments:
            cid = comment.id
            author = comment.author.displayName
            time = datetime.strptime(comment.created, "%Y-%m-%dT%H:%M:%S.000+0800")
            time_str = comment.created[:10]
            content = comment.body
            if content.find("[gpt_finding_response]") >= 0:
                self.mb_finding_response = True
            if content.find("[gpt_prompt]") >= 0:
                continue
            fed_data['comments'].append({
                'cid': cid,
                'author': author,
                'time': time_str,
                'content': content
            })

        ### extract attachments
        from pkg._util.util_file import unzip_and_get_file_paths
        from pkg._qjira.comment import file_text_content

        # 列出可出抽取文字資訊的檔案
        text_files = self.download_attachments(
            downloads, analysis_task.is_text_info_included
        )
        # 列出可出壓縮檔案
        zip_files = self.download_attachments(downloads, analysis_task.is_zip_file)

        # 解壓縮並找出可出抽取文字資訊的檔案
        for zip_file in zip_files:
            extracted_files = unzip_and_get_file_paths(
                zip_file, os.path.dirname(zip_file)
            )
            for extracted_file in extracted_files:
                if (
                    extracted_file.lower().endswith(".txt")
                    or extracted_file.lower().endswith(".py")
                    or extracted_file.lower().endswith(".sh")
                    or extracted_file.lower().endswith(".md")
                    or extracted_file.lower().endswith(".pdf")
                    or extracted_file.lower().endswith(".docx")
                ):
                    text_files.append(extracted_file)

        # 抽出文字資訊
        the_attachments = []
        for text_based_file in text_files:
            the_content = { 
                'filename': text_based_file,
                'content':   file_text_content(text_based_file)
            }
            the_attachments.append(the_content)

        return the_prompt, fed_data, the_attachments

        '''
        the_prompt:         none or str
        fed_data: {
            'summary':      str,
            'description':  str,
            'vauthor':      str,
            'comments':     [
                'cid':      str,
                'author':   str,
                'time':     str,
                'content':  str,
            ],
        },
        the_attachments: [
            {
                'filename': str,
                'content':  str,
            },
        ]
        '''
