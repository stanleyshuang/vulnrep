#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2021-06-13
#
import json
from datetime import datetime
from pkg._util.util_datetime import duration_days
from .description import extract_model
from . import i_issue, get_issuetype


class i_bug(i_issue):
    """
    Jira bug
    """

    def __init__(self, jira, issue, debug_mode):
        super(i_bug, self).__init__(jira, issue, debug_mode)
        if get_issuetype(self.issue) != "Bug":
            raise Exception("Jira issuetype mismatch!!")


class vuln_bug(i_bug):
    """
    Jira bug for vulnerabilty fixing
    """

    def __init__(self, jira, issue, debug_obj):
        super(vuln_bug, self).__init__(jira, issue, debug_obj)
        self.labtest_date = None
        self.release_date = None
        self.labtest_num = 0
        self.released_num = 0
        self._b_fix_status = "not_fixed"

    def set_status(self, parent_issue, raw):
        self.debuglog_i("[Bug-{key}] Update Status".format(key=self.issue.key))
        dict_customfield_13600 = {}

        ### Update Task Raw
        dict_customfield_13600["RAW"] = raw

        # Status Update: customfield_13600
        str_customfield_13600 = None  # json.dumps(dict_customfield_13600, indent=4)
        if self.issue.raw["fields"]["customfield_13600"] != str_customfield_13600:
            self.debuglog_r(
                "--- update Status Update (customfield_13600): [{data}]".format(
                    data=self.issue.raw["fields"]["customfield_13600"]
                )
            )
            self.issue.update(fields={"customfield_13600": str_customfield_13600})

        # PgM Project Update: customfield_13601
        # Sync Summary with the Jira Task
        if (
            parent_issue
            and parent_issue.issue.fields.summary.lower().find("[main]") < 0
            and self.get_status_name() not in ["abort", "verified"]
        ):
            from pkg._qjira.description import sync_summary_content

            synced = sync_summary_content(
                parent_issue.issue.fields.summary, self.issue.fields.summary
            )
            """
            if synced!=self.issue.fields.summary:
                self.debuglog_r('    Bug Summary sync with Task: [{synced}]'.format(synced=synced))
                self.issue.update(fields={'summary': synced})
            """
            if (
                "customfield_16401" in self.issue.raw["fields"]
                and "customfield_16401" in parent_issue.issue.raw["fields"]
                and self.issue.raw["fields"]["customfield_16401"]
                != parent_issue.issue.raw["fields"]["customfield_16401"]
            ):
                original_deadline_str = self.issue.raw["fields"]["customfield_16401"]
                deadline_str = parent_issue.issue.raw["fields"]["customfield_16401"]
                if original_deadline_str:
                    self.debuglog_r(
                        "--- Original Deadline                    "
                        + original_deadline_str
                    )
                if deadline_str:
                    self.issue.update(fields={"customfield_16401": deadline_str})
                    self.debuglog_r(
                        "--- Update Release Deadline              {deadline_str}".format(
                            deadline_str=deadline_str
                        )
                    )

        if self.issue.fields.summary.find("QuTS hero") >= 0:
            i_issue.add_watchers(
                self.jira, self.issue, ["CyChen@qnap.com", "IrisChen@qnap.com"]
            )
        if self.issue.fields.summary.find("QTS") >= 0:
            i_issue.add_watchers(self.jira, self.issue, ["SeanChang@qnap.com"])
        if (
            self.issue.fields.summary.find("QuTScloud") >= 0
            or self.issue.fields.summary.find("QuTS cloud") >= 0
        ):
            i_issue.add_watchers(self.jira, self.issue, ["AndyFung@qnap.com"])
        """
        watchers = self.issue.raw['fields']["customfield_14000"]
        for watcher in watchers:
            print(str(watcher))
        """

    def get_gsheet_raw(self):
        from pkg._util.util_datetime import utc_to_local_str

        now = datetime.now()
        raw = {}
        created_time, str_created_time = self.get_created_n_str()
        rd, resolved, status = self.get_auther_and_created_in_changlog(
            "status", ["resolved"]
        )
        dqv, verified, status = self.get_auther_and_created_in_changlog(
            "status", ["verified"]
        )

        if self.get_status_name() not in ["verified", "abort"]:
            if rd and resolved:
                resolved_time, str_resolved_time = self.get_time_n_str(resolved)
                raw = {
                    "created": str_created_time,
                    "key": self.issue.key,
                    "rd": rd,
                    "resolved": str_resolved_time,
                    "resolved_days": duration_days(created_time, resolved_time),
                    "status": self.get_status_name(),
                    "summary": self.issue.fields.summary,
                }
            else:
                raw = {
                    "created": str_created_time,
                    "key": self.issue.key,
                    "status": self.get_status_name(),
                    "summary": self.issue.fields.summary,
                }
        elif self.get_status_name() in ["abort"]:
            raw = {
                "created": str_created_time,
                "key": self.issue.key,
                "resolved_days": 0,
                "verified_days": 0,
                "status": self.get_status_name(),
                "summary": self.issue.fields.summary,
            }
        else:
            resolved_time, str_resolved_time = self.get_time_n_str(resolved)
            verified_time, str_verified_time = self.get_time_n_str(verified)
            raw = {
                "created": str_created_time,
                "key": self.issue.key,
                "rd": rd,
                "resolved": str_resolved_time,
                "resolved_days": duration_days(created_time, resolved_time),
                "dqv": dqv,
                "verified": str_verified_time,
                "verified_days": duration_days(resolved_time, verified_time),
                "status": self.get_status_name(),
                "summary": self.issue.fields.summary,
            }

        if self.labtest_date:
            labtest_date, raw["labtest"] = self.get_time_n_str(
                self.labtest_date, s_format="%Y-%m-%d"
            )
        if self.release_date:
            release_date, raw["released"] = self.get_time_n_str(
                self.release_date, s_format="%Y-%m-%d"
            )
        if self.labtest_date and self.release_date:
            raw["duration"] = duration_days(labtest_date, release_date)
        elif self.labtest_date:
            raw["duration"] = duration_days(labtest_date, now)
        raw["labtest_num"] = str(self.labtest_num - self.released_num)
        raw["released_num"] = str(self.released_num)
        if self.release_date:
            raw["overall_duration"] = duration_days(created_time, release_date)
        elif self._b_fix_status == "not_affected":
            raw["overall_duration"] = raw["resolved_days"]
        else:
            raw["overall_duration"] = duration_days(created_time, now)
        if (
            self._b_fix_status == "fixed" and self.released_num > 0
        ) or self._b_fix_status == "not_affected":  # PM 確認修復，無影響，不成立，
            raw["done"] = "Yes"
        else:
            raw["done"] = "No"
        if self._b_fix_status == "fixed":  # DQV 確認修復，無影響，不成立，
            raw["fixed"] = "Yes"
        else:
            raw["fixed"] = "No"
        if self._b_fix_status == "not_affected":
            raw["affected"] = "No"
        else:
            raw["affected"] = "Yes"
        return raw

    def trace_dependency(self):
        from .releaseproc import (
            fw_release_process,
            fw_delivery_process,
            app_release_process,
        )

        if self.b_dependency_traced:
            return
        self.b_dependency_traced = True
        self.dependent_counts = 0
        self.dependent_issues = []
        self.search_blocking()
        for blocking_issue in self.blocking_issues:
            if get_issuetype(blocking_issue) == "App Release Process":
                the_apprelease = app_release_process(
                    self.jira, blocking_issue, self.debug_obj
                )
                self.dependent_counts += 1
                self.dependent_issues.append(the_apprelease)
            elif get_issuetype(blocking_issue) == "FW Release Process":
                the_fwrelease = fw_release_process(
                    self.jira, blocking_issue, self.debug_obj
                )
                self.dependent_counts += 1
                self.dependent_issues.append(the_fwrelease)
            elif get_issuetype(blocking_issue) == "FW Delivery Process":
                the_fwdelivery = fw_delivery_process(
                    self.jira, blocking_issue, self.debug_obj
                )
                self.dependent_counts += 1
                self.dependent_issues.append(the_fwdelivery)
            elif get_issuetype(blocking_issue) == "Product Testing Task":
                the_fwrelease = fw_release_process(
                    self.jira, blocking_issue, self.debug_obj
                )
                self.dependent_counts += 1
                self.dependent_issues.append(the_fwrelease)
        self.search_blocked()
        for blocked_issue in self.blocked_issues:
            if get_issuetype(blocked_issue) == "App Release Process":
                the_apprelease = app_release_process(
                    self.jira, blocked_issue, self.debug_obj
                )
                self.dependent_counts += 1
                self.dependent_issues.append(the_apprelease)
            elif get_issuetype(blocked_issue) == "FW Release Process":
                the_fwrelease = fw_release_process(
                    self.jira, blocked_issue, self.debug_obj
                )
                self.dependent_counts += 1
                self.dependent_issues.append(the_fwrelease)
            elif get_issuetype(blocked_issue) == "FW Delivery Process":
                the_fwdelivery = fw_delivery_process(
                    self.jira, blocked_issue, self.debug_obj
                )
                self.dependent_counts += 1
                self.dependent_issues.append(the_fwdelivery)
            elif get_issuetype(blocked_issue) == "Product Testing Task":
                the_fwrelease = fw_release_process(
                    self.jira, blocked_issue, self.debug_obj
                )
                self.dependent_counts += 1
                self.dependent_issues.append(the_fwrelease)

    def at_completed_states(self):
        status = self.get_status_name()
        return (
            status == "verified"
            and (
                self.released_num > 0
                or self.issue.raw["fields"]["resolution"]["name"] == "Won't Fix"
            )
        ) or status == "abort"

    def run(self, root_issue, parent_issue, data, downloads, b_update=False):
        from .releaseproc import (
            fw_release_process,
            fw_delivery_process,
            app_release_process,
        )

        self.trace_dependency()

        ### 準備 dependent_issues
        dependent_issues = []
        b_resolved = False
        """
        b_add_component_vulnerability_report = False
        if b_update and self.does_component_exit('vulnerability_report'):
            b_add_component_vulnerability_report = True
        """
        if self.issue.raw["fields"]["customfield_16900"]:
            for item in self.issue.raw["fields"]["customfield_16900"]:
                issue = self.jira.issue(item["key"], expand="changelog")
                if get_issuetype(issue) == "App Release Process":
                    the_apprelease = app_release_process(
                        self.jira, issue, self.debug_obj
                    )
                    dependent_issues.append(the_apprelease)
                    """
                    if b_add_component_vulnerability_report:
                        the_apprelease.add_component('vulnerability_report')
                    """
                elif get_issuetype(issue) == "FW Release Process":
                    the_fwrelease = fw_release_process(self.jira, issue, self.debug_obj)
                    dependent_issues.append(the_fwrelease)
                    """
                    if b_add_component_vulnerability_report:
                        the_fwrelease.add_component('vulnerability_report')
                    """

        # if len(dependent_issues)==0:
        dependent_issues.extend(self.dependent_issues)

        ### 展開 raws, labtest_dates, release_dates
        raws = []
        for issue in dependent_issues:
            if get_issuetype(issue.issue) == "App Release Process":
                children = issue.run(root_issue, self, data, downloads, b_update)
                raws.extend(children)
            elif get_issuetype(issue.issue) == "FW Release Process":
                children = issue.run(root_issue, self, data, downloads, b_update)
                raws.extend(children)
            elif get_issuetype(issue.issue) == "FW Delivery Process":
                raw = issue.run(root_issue, self, data, downloads, b_update)
                raws.append(raw)
        labtest_dates = []  # ARP, FRP and FDP 的創建時間
        release_dates = []  # ARP, FRP and FDP 的完成時間
        for raw in raws:
            if "created" not in raw:
                self.debuglog_r("   !! [EXCEPTION] DUMP {raw}".format(raw=str(raw)))
                continue
            labtest_dates.append(raw["created"])
            if "completed" in raw:
                release_dates.append(raw["completed"])
                b_resolved = True

        # lab testing date
        labtest_dates = sorted(labtest_dates)
        if len(labtest_dates) > 0:
            self.labtest_date = labtest_dates[0]
        # release date
        release_dates = sorted(release_dates)
        if len(release_dates) > 0:
            self.release_date = release_dates[len(release_dates) - 1]
        # labtest num
        self.labtest_num = len(labtest_dates)
        # release num
        self.released_num = len(release_dates)

        model, product, ver = extract_model(self.issue.fields.summary)
        labels = self.issue.raw["fields"]["labels"]
        ### 了解狀態 b_resolved, self._b_fix_status
        if self.get_status_name() in ["verified"]:
            if b_resolved:
                self._b_fix_status = "fixed"
                model, product, ver = extract_model(self.issue.fields.summary)
                self.debuglog_r(
                    "   ** [Bug-{key}] - [{product}] fixed".format(
                        key=self.issue.key, product=product
                    )
                )
            else:
                resolution = self.issue.raw["fields"]["resolution"]["name"]
                if resolution in ["Won't Fix", "INVALID", "Duplicate"]:
                    self._b_fix_status = "not_affected"
                    model, product, ver = extract_model(self.issue.fields.summary)
                    self.debuglog_r(
                        "   ** [Bug-{key}] - [{product}] {resolution}".format(
                            key=self.issue.key, product=product, resolution=resolution
                        )
                    )
                else:
                    b_printed = False
                    for label in labels:
                        if label in ["production_web_verified"]:
                            self._b_fix_status = "fixed"
                            model, product, ver = extract_model(
                                self.issue.fields.summary
                            )
                            self.debuglog_r(
                                "   ** [Bug-{key}] - [{product}] Web Production Verified".format(
                                    key=self.issue.key, product=product
                                )
                            )
                            b_printed = True
                            break
                        elif label in ["not_released"]:
                            self._b_fix_status = "not_affected"
                            model, product, ver = extract_model(
                                self.issue.fields.summary
                            )
                            self.debuglog_r(
                                "   ** [Bug-{key}] - [{product}] Non-released".format(
                                    key=self.issue.key, product=product
                                )
                            )
                            b_printed = True
                            break
                    if not b_printed:
                        self.debuglog_r(
                            "   -- [Bug-{key}] - [{product}]".format(
                                key=self.issue.key, product=product
                            )
                        )
        elif self.get_status_name() in ["abort"]:
            self._b_fix_status = "not_affected"
            self.debuglog_r(
                "   ** [Bug-{key}] - [{product}] ABORT".format(
                    key=self.issue.key, product=product
                )
            )
        elif self.get_status_name() in ["resolved"]:
            if b_resolved:
                self._b_fix_status = "fixed"
                model, product, ver = extract_model(self.issue.fields.summary)
                self.debuglog_r(
                    "   >> [Bug-{key}] - [{product}] bug unresolved, but release process done".format(
                        key=self.issue.key, product=product
                    )
                )
            else:
                if self.labtest_num != 0:
                    self.debuglog_r(
                        "   -- [Bug-{key}] - [{product}] unresolved, and release process in process".format(
                            key=self.issue.key, product=product
                        )
                    )
        else:
            b_printed = False
            for label in labels:
                if label in ["transfer_to_requirement"]:
                    self._b_fix_status = "fixed"
                    model, product, ver = extract_model(self.issue.fields.summary)
                    self.debuglog_r(
                        "   ** [Bug-{key}] - [{product}] Transfer to Requirement".format(
                            key=self.issue.key, product=product
                        )
                    )
                    b_printed = True
                    break
            if not b_printed:
                self.debuglog_r(
                    "   -- [Bug-{key}] - [{product}] {status}".format(
                        key=self.issue.key,
                        product=product,
                        status=self.get_status_name(),
                    )
                )

        if self._b_fix_status == "not_fixed" and self.labtest_num == 0:
            dpms = [
                "amberchen@qnap.com",
                "irischen@qnap.com",
                "seanchang@qnap.com",
                "cychen@qnap.com",
                "harulin@qnap.com",
                "andyhuang@qnap.com",
                "ritatsai@qnap.com",
                "violatseng@qnap.com",
            ]
            dqvs = ["chocoliang@qnap.com"]
            # bug 未解且無 labtest
            owner, str_long_time, status = self.get_auther_and_created_in_changlog(
                "status", ["resolved"]
            )
            if str_long_time and self.issue.fields.assignee.name in dpms:
                # 已達 resolved 的 jira
                the_time, str_time = self.get_time_n_str(str_long_time)
                model, product, ver = extract_model(self.issue.fields.summary)
                if self.issue.fields.summary.lower().find("[qnap cloud service]") < 0:
                    # 非 cloud team jira 狀態達 resolved
                    self._b_fix_status = "fixed"
                    self.debuglog_r(
                        "   *> [Bug-{key}] - [{product}] resolved, Wait for FW/App Release Process".format(
                            key=self.issue.key, product=product
                        ),
                        since=the_time,
                    )
                else:
                    self.debuglog_r(
                        "   >> [Bug-{key}] - [{product}] unresolved, No FW/App Release Process ({assignee})".format(
                            key=self.issue.key,
                            product=product,
                            assignee=print(self.issue.fields.assignee.name),
                        ),
                        since=the_time,
                    )
            elif (
                str_long_time
                and self.issue.fields.assignee.name in dqvs
                and self.issue.fields.summary.lower().find("[qnap cloud service]") >= 0
            ):
                # 已達 resolved 的 jira
                the_time, str_time = self.get_time_n_str(str_long_time)
                model, product, ver = extract_model(self.issue.fields.summary)
                self._b_fix_status = "fixed"
                self.debuglog_r(
                    "   ** [Bug-{key}] - [{product}] resolved and verified".format(
                        key=self.issue.key, product=product
                    ),
                    since=the_time,
                )
            else:
                # 未達 resolved 的 jira
                the_time, str_time = self.get_created_n_str()
                model, product, ver = extract_model(self.issue.fields.summary)
                self.debuglog_r(
                    "   >> [Bug-{key}] - [{product}] unresolved RD is fixing..".format(
                        key=self.issue.key, product=product
                    ),
                    since=the_time,
                )
        ### update Status Update
        raw = self.get_gsheet_raw()
        if b_update:
            self.set_status(parent_issue, raw)
        return raw, raws

    def check(self, root_issue, parent_issue, data, downloads, b_update=False):
        raw, raws = self.run(
            root_issue, parent_issue, data, downloads, b_update=b_update
        )
        return raw, raws

    def find_task(self):
        issues = self.search_clones()
        for issue in issues:
            if get_issuetype(issue) == "Task":
                return issue
        issues = self.search_blocking()
        for issue in issues:
            if get_issuetype(issue) == "Task":
                return issue
        return None
