#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 2.0
# Date:     2022-05-14
#
from . import cve

import datetime


class json_5_0(cve):
    def __init__(self, issuekey, qsa, gsheet, qsa_id, summary):
        super(json_5_0, self).__init__(issuekey, qsa, gsheet, qsa_id, summary)

    def __init__(self, obj, gsheet, qsa_id, summary):
        qsa = {}
        qsa["analysis"] = obj.analysis_obj
        qsa["task"] = obj.task_obj
        qsa["releaseissue"] = obj.releaseissue_obj
        qsa["gsheet"] = obj.gsheet_obj
        super(json_5_0, self).__init__(obj.issuekey, qsa, gsheet, qsa_id, summary)
        self.cve_json_filename = obj.cve_json_filename
        self.description = obj.description
        self.solution = obj.solution

    def cve_json_complete(self, cve_dict):
        if "containers" in cve_dict:
            cve_dict["containers"] = self.containers(cve_dict["containers"])
        else:
            cve_dict["containers"] = self.containers({})
        cve_dict["cveMetadata"]["cveId"] = self.filename
        # 如果 CVSS 套用 4.0，dataVersion 要調整為 5.1.0
        if "metrics" in cve_dict["containers"]["cna"]:
            metrics = cve_dict["containers"]["cna"]["metrics"]
            for metric in metrics:
                if "cvssV4_0" in metric:
                    cve_dict["dataVersion"] = "5.1.0"
                    break
        return cve_dict

    def containers(self, containers):
        if "cna" in containers:
            containers["cna"] = self.cna(containers["cna"])
        else:
            containers["cna"] = self.cna({})
        return containers

    def cna(self, cna):
        cna["affected"] = self.affected()
        credits = self.credits()
        if credits:
            cna["credits"] = credits

        description = self.descriptions()
        if description:
            cna["descriptions"] = description
        elif "descriptions" in cna:
            cna.pop("descriptions", None)

        impacts = self.impacts()
        if impacts:
            cna["impacts"] = self.impacts()
        elif "impacts" in cna:
            cna.pop("impacts", None)

        metrics = self.metrics()
        if metrics:
            cna["metrics"] = self.metrics()
        elif "metrics" in cna:
            cna.pop("metrics", None)

        problemTypes = self.problemTypes()
        if problemTypes:
            cna["problemTypes"] = problemTypes
        elif "problemTypes" in cna:
            cna.pop("problemTypes", None)

        cna["references"] = self.references()

        solutions = self.solutions()
        if solutions:
            cna["solutions"] = solutions
        elif "solutions" in cna:
            cna.pop("solutions", None)

        cna["source"] = self.source()
        cna["title"] = self.title()
        return cna

    def affected(self):
        affected = []
        for product in self.releaseissue_obj["product_data"]:
            versions = []
            platforms = []
            for version_data in product["version"]["version_data"]:
                version = {}
                if version_data["version_affected"] == "<":
                    version["lessThan"] = version_data["version_value"]
                    version["status"] = "affected"
                    version["version"] = version_data["version_begin"]
                    version["versionType"] = "custom"
                elif version_data["version_affected"] == "<=":
                    version["lessThanOrEqual"] = version_data["version_value"]
                    version["status"] = "affected"
                    version["version"] = version_data["version_begin"]
                    version["versionType"] = "custom"
                elif version_data["version_affected"] == "x":
                    version["status"] = "unaffected"
                    version["version"] = version_data["version_begin"]
                if (
                    "platform" in version_data
                    and version_data["platform"]
                    and len(version_data["platform"]) > 0
                ):
                    platforms.append(version_data["platform"])
                versions.append(version)

            affected_item = {}
            affected_item["defaultStatus"] = "unaffected"
            if len(platforms) > 0:
                affected_item["platforms"] = platforms
            affected_item["product"] = product["product_name"]
            affected_item["vendor"] = "QNAP Systems Inc."
            affected_item["versions"] = versions

            affected.append(affected_item)
        return affected

    def credits(self):
        if self.gsheet_obj is None or "credit" not in self.gsheet_obj:
            return None
        credits = []
        credit = {
            "lang": "en",
            "type": "finder",
        }
        credit["value"] = self.gsheet_obj["credit"]
        credits.append(credit)
        return credits

    def descriptions(self):
        if not self.description or len(self.description) == 0:
            return None
        supportingMedia = []
        supportingMedia_item = {}
        supportingMedia_item["base64"] = False
        supportingMedia_item["type"] = "text/html"
        supportingMedia_item["value"] = self.description.replace("\n", "<br>")

        supportingMedia.append(supportingMedia_item)

        descriptions = []
        description = {}
        description["lang"] = "en"
        description["supportingMedia"] = supportingMedia
        description["value"] = self.description
        descriptions.append(description)
        return descriptions

    def impacts(self):
        impacts = []
        if "capecids" in self.analysis_obj and self.analysis_obj["capecids"]:
            capecids = self.analysis_obj["capecids"]
        else:
            return None
        for capecid in capecids:
            impact = {}
            impact["capecId"] = capecid
            impact["descriptions"] = [{"lang": "en", "value": capecid}]
            impacts.append(impact)
        return impacts

    def metrics(self):
        metrics = []
        metric = {}
        cvssVX_X = cve.cvss(
            self.analysis_obj["cvssv3_vec"], self.analysis_obj["cvssv3_score"]
        )
        if not bool(cvssVX_X):
            return None

        if cvssVX_X["version"] == "3.1":
            metric["cvssV3_1"] = cvssVX_X
        else:
            metric["cvssV4_0"] = cvssVX_X

        metric["format"] = "CVSS"
        metric["scenarios"] = [{"lang": "en", "value": "GENERAL"}]
        metrics.append(metric)
        return metrics

    def problemTypes(self):
        if (
            self.analysis_obj is None
            or "cweids" not in self.analysis_obj
            or self.analysis_obj["cweids"] is None
        ):
            return None

        descriptions = []
        for cweid in self.analysis_obj["cweids"]:
            description = {"lang": "en", "type": "CWE"}
            description["cweId"] = cweid
            description["description"] = cweid
            descriptions.append(description)

        problemTypes = []
        problemType = {}
        problemType["descriptions"] = descriptions
        problemTypes.append(problemType)
        return problemTypes

    def references(self):
        references = []
        reference = {}
        reference["url"] = self.qsa_url
        references.append(reference)
        return references

    def solutions(self):
        if not self.solution or len(self.solution) == 0:
            return None
        supportingMedia = []
        supportingMedia_item = {}
        supportingMedia_item["base64"] = False
        supportingMedia_item["type"] = "text/html"
        supportingMedia_item["value"] = self.solution.replace("\n", "<br>")

        supportingMedia.append(supportingMedia_item)

        solutions = []
        solution = {}
        solution["lang"] = "en"
        solution["supportingMedia"] = supportingMedia
        solution["value"] = self.solution
        solutions.append(solution)
        return solutions

    def source(self):
        source = {}
        source["advisory"] = self.qsa_id
        source["discovery"] = "EXTERNAL"
        return source

    def title(self):
        return self.releaseissue_obj["sa_title"]
