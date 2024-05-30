# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 2.0
# Date:     2023-02-13
#
import re
from . import permanent_obj


class vglobalconfig(permanent_obj):
    """{
        "last_analyst_index": 0,
        "analyst_list": ["KevinLiao@qnap.com", "MyronSu@qnap.com"],
    }"""

    def __init__(
        self, data, downloads, filename="global_config.json", service="common"
    ):
        super(vglobalconfig, self).__init__(data, downloads, filename, service)
        whole = self.load("global")
        if whole == None:
            whole = {
                "last_analyst_index": 0,
                "analyst_list": ["KevinLiao@qnap.com", "MyronSu@qnap.com"],
                "latest_qsaid_idx": "QSA-24-01",
            }
            self.update("global", whole)

    def select_analyst(self, model, email=None):
        whole = self.json_obj
        analyst_list = whole["analyst_list"]
        ### init whole['analyst_job_count']
        if "analyst_job_count" not in whole:
            whole["analyst_job_count"] = {}
        ### pick the one who's counts are smallest
        candidate = None
        min_count = 1000000.0
        if email:
            candidate = self.find_owner(email)
            if candidate:
                min_count = whole["analyst_job_count"][candidate]
                print(
                    "分析師： "
                    + candidate
                    + "，已處理 {:.2f} 件工作。專責負責研究員 ({}) 的弱點報告".format(min_count, email)
                )
        if candidate is None:
            if model in [
                "qts",
                "quts hero",
                "qutscloud",
                "qpkg",
                "qne",
                "qvp",
                "qvr",
                "qes",
                "main",
            ]:
                for analyst in analyst_list:
                    # init whole['analyst_job_count'][analyst]
                    if analyst not in whole["analyst_job_count"]:
                        whole["analyst_job_count"][analyst] = 0.0
                    # compare with min_count
                    if whole["analyst_job_count"][analyst] < min_count:
                        candidate = analyst
                        min_count = whole["analyst_job_count"][analyst]
                self.flush("global")
                print(
                    "分析師： " + candidate + "，已處理 {:.2f} 件工作。".format(min_count)
                )
            else:
                candidate = "KevinLiao@qnap.com"
                print("分析師： " + candidate + "，model: " + model + "。")

        return candidate

    def assign_analyst(self, assignee, weight=1.0):
        whole = self.json_obj
        analyst_list = whole["analyst_list"]
        ### init whole['analyst_job_count']
        if "analyst_job_count" not in whole:
            whole["analyst_job_count"] = {}
        ### init whole['analyst_job_count'][analyst]
        if assignee not in whole["analyst_job_count"]:
            whole["analyst_job_count"][assignee] = 0.0
        # job counts increased
        whole["analyst_job_count"][assignee] += weight
        self.flush("global")

    def find_owner(self, email):
        whole = self.json_obj
        researcher_2_analyst = whole["researcher_2_analyst"]
        if email in researcher_2_analyst:
            return researcher_2_analyst[email]
        else:
            return None
