#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 2.0
# Date:     2022-05-14
#
from . import cve

import datetime


class json_4_0(cve):
    def __init__(self, issuekey, qsa, gsheet, qsa_id, summary):
        super(json_4_0, self).__init__(issuekey, qsa, gsheet, qsa_id, summary)

    def __init__(self, obj, gsheet, qsa_id, summary):
        qsa = {}
        qsa["analysis"] = obj.analysis_obj
        qsa["task"] = obj.task_obj
        qsa["releaseissue"] = obj.releaseissue_obj
        qsa["gsheet"] = obj.gsheet_obj
        super(json_4_0, self).__init__(obj.issuekey, qsa, gsheet, qsa_id, summary)
        self.cve_json_filename = obj.cve_json_filename
        self.description = obj.description
        self.solution = obj.solution

    @property
    def filename(self):
        return self.analysis_obj["extracted_cveid"]

    @staticmethod
    def cve_json_impact(cvssv3_vec, cvssv3_score):
        cvss = cve.cvss(cvssv3_vec, cvssv3_score)
        cve_dict_impact = {}
        cve_dict_impact["cvss"] = cvss
        if cvss and bool(cvss):
            return cve_dict_impact
        return None

    def cve_json_complete(self, cve_dict):
        cveid = self.analysis_obj["extracted_cveid"]
        date_public = self.cve_publish
        title = self.releaseissue_obj["sa_title"]
        product_data = self.releaseissue_obj["product_data"]
        url = self.qsa_url
        if self.gsheet_obj and "credit" in self.gsheet_obj:
            credit = self.gsheet_obj["credit"]
        else:
            credit = None
        qsa_id = self.qsa_id
        cweids = self.analysis_obj["cweids"]
        cvssv3_vec = self.analysis_obj["cvssv3_vec"]
        cvssv3_score = self.analysis_obj["cvssv3_score"]
        description = self.description
        solution = self.solution

        if "CVE_data_meta" not in cve_dict:
            cve_dict["CVE_data_meta"] = {}
        cve_data_meta = cve_dict["CVE_data_meta"]
        cve_data_meta["ID"] = cveid
        cve_data_meta["ASSIGNER"] = "security@qnap.com"
        """
        if date_public and len(date_public)>0:
            cve_data_meta["DATE_PUBLIC"] = date_public
        else:
            cve_data_meta["DATE_PUBLIC"] = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.000Z")
        """
        cve_data_meta["TITLE"] = title

        if "affects" not in cve_dict:
            cve_dict["affects"] = {}
        if "vendor" not in cve_dict["affects"]:
            cve_dict["affects"]["vendor"] = {}
        if "vendor_data" not in cve_dict["affects"]["vendor"]:
            cve_dict["affects"]["vendor"]["vendor_data"] = []
            first_vendor = {}
            cve_dict["affects"]["vendor"]["vendor_data"].append(first_vendor)
        first_vendor = cve_dict["affects"]["vendor"]["vendor_data"][0]

        if "vendor_name" not in first_vendor:
            first_vendor["vendor_name"] = "QNAP Systems Inc."
        if "product" not in first_vendor:
            first_vendor["product"] = {}
        product_data_clone = product_data
        for product in product_data_clone:
            versions = product["version"]["version_data"]
            for version in versions:
                if version["version_affected"] == "x":
                    version["version_affected"] = "!"
                    version["version_value"] = version["version_begin"]
                elif version["version_affected"] == "<":
                    pass
                else:
                    pass
                version.pop("platform", None)
                version.pop("version_begin", None)

        first_vendor["product"]["product_data"] = product_data_clone
        cve_dict["affects"]["vendor"]["vendor_data"][0] = first_vendor

        ### "description" --> "description_data" --> [0] --> "value"
        if "description" not in cve_dict:
            cve_dict["description"] = {}
        if "description_data" not in cve_dict["description"]:
            cve_dict["description"]["description_data"] = []
        if len(cve_dict["description"]["description_data"]) == 0:
            cve_dict["description"]["description_data"].append(
                {
                    "lang": "eng",
                }
            )
        cve_dict["description"]["description_data"][0]["value"] = description

        ### "references" --> "reference_data" --> [0] --> "url"
        if "references" not in cve_dict:
            cve_dict["references"] = {}
        if "reference_data" not in cve_dict["references"]:
            cve_dict["references"]["reference_data"] = []
        if len(cve_dict["references"]["reference_data"]) == 0:
            cve_dict["references"]["reference_data"].append(
                {
                    "refsource": "CONFIRM",
                }
            )
        cve_dict["references"]["reference_data"][0]["url"] = url

        ### "solution" --> [0] --> "value"
        if "solution" not in cve_dict:
            cve_dict["solution"] = []
        if len(cve_dict["solution"]) == 0:
            cve_dict["solution"].append(
                {
                    "lang": "eng",
                }
            )
        cve_dict["solution"][0]["value"] = solution

        ### "credit" --> [0] --> "value"
        if credit and len(credit) > 0:
            if "credit" not in cve_dict:
                cve_dict["credit"] = []
            if len(cve_dict["credit"]) == 0:
                cve_dict["credit"].append(
                    {
                        "lang": "eng",
                    }
                )
            cve_dict["credit"][0]["value"] = credit

        ### "source" --> [0] --> "value"
        if "source" not in cve_dict:
            cve_dict["source"] = {}
        cve_dict["source"]["advisory"] = qsa_id
        cve_dict["source"]["discovery"] = "EXTERNAL"

        ### CWE IDs
        if cweids:
            i = 0
            for cweid in cweids:
                problem_types = cve_dict["problemtype"]["problemtype_data"]
                if i < len(problem_types):
                    problem_types[i]["description"][0]["value"] = cweid
                else:
                    problem_types.append(
                        {"description": [{"lang": "eng", "value": cweid}]}
                    )
                i += 1
            cve_dict["problemtype"]["problemtype_data"] = problem_types
        else:
            cve_dict.pop("problemtype", None)

        ### CVSSv3 Score
        impact = json_4_0.cve_json_impact(cvssv3_vec, cvssv3_score)
        if impact:
            cve_dict["impact"] = impact
        elif "impact" in cve_dict:
            cve_dict.pop("impact", None)
        return cve_dict
