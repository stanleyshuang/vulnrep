#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 2.0
# Date:     2022-04-05
#
import datetime, os, re, shutil


class cve:
    def __init__(self, issuekey, qsa, gsheet, qsa_id, summary):
        self.analysis_obj = qsa["analysis"]
        self.task_obj = qsa["task"]
        self.releaseissue_obj = qsa["releaseissue"]
        if "product_data" not in self.releaseissue_obj:
            self.releaseissue_obj["product_data"] = []
        self.gsheet_obj = qsa.get("gsheet", None)
        self.issuekey = issuekey
        self.cve_json_filename = None
        self.description = ""
        self.solution = ""
        self.b_3rdparty = summary.find("(3rd-party)") >= 0
        self._gsheet = gsheet
        self._qsa = None
        self._qsa_id = qsa_id
        self.summary = summary

    @property
    def filename(self):
        return self.analysis_obj["extracted_cveid"]

    @property
    def qsa_id(self):
        if self._qsa and self._qsa[3] and len(self._qsa[3]) > 0:
            return self._qsa[3]
        else:
            qsa = self._gsheet.search_qsa_dashboard(self.issuekey)
            if qsa:
                self._qsa = qsa
                if self._qsa[3] and len(self._qsa[3]) > 0:
                    return self._qsa[3]
            if self._qsa_id:
                return self._qsa_id
        return None

    @property
    def cve_publish(self):
        if self._qsa:
            if self._qsa[9] and len(self._qsa[9]) > 0:
                return self._qsa[9]
        else:
            qsa = self._gsheet.search_qsa_dashboard(self.issuekey)
            if qsa:
                self._qsa = qsa
                if self._qsa[9] and len(self._qsa[9]) > 0:
                    return self._qsa[9]
        return None

    @property
    def qsa_url(self):
        qsa_id = self.qsa_id
        if qsa_id:
            return "https://www.qnap.com/en/security-advisory/" + qsa_id.lower()
        return None

    def ensure_file_exist(self, data, downloads):
        from pkg._util.util_file import create_folder

        if not self.filename:
            return  # analysis is not available

        ### check the CVE JSON file
        json_location = os.path.join(downloads, "jira", self.issuekey)
        create_folder(json_location)
        self.cve_json_filename = os.path.join(json_location, f"{self.filename}.json")

        if not os.path.isfile(self.cve_json_filename):
            null_json = os.path.join(data, "null.json")
            if os.path.isfile(null_json):
                shutil.copyfile(null_json, self.cve_json_filename)

    @property
    def is_3rdparty_vul(self):
        return self.b_3rdparty

    @property
    def are_multiple_cveids(self):
        return "|" in self.analysis_obj["extracted_cveid"]

    def prepare_content(self, cve_json_files):
        from pkg._util.util_text_file import open_json, dump_json

        if not self.cve_json_filename or not os.path.isfile(self.cve_json_filename):
            print("JSON 檔案不存在")
            return None  # file not exist, don't upload

        if self.cve_json_filename not in cve_json_files:
            print("加入檔案：" + self.cve_json_filename)
            cve_json_files.append(self.cve_json_filename)

        print("尋找：" + self.filename)
        for cve_json_file in cve_json_files:
            # modify cve json
            path_add_cveid, json_ext = os.path.splitext(cve_json_file)

            if self.filename not in path_add_cveid:
                continue

            ### project to read QSA ID, Product, version and credit from Google Sheet
            if self.analysis_obj and self.task_obj and self.releaseissue_obj:
                if "product_data" in self.releaseissue_obj:
                    (
                        str_vul_description,
                        str_affected_product_names,
                        str_not_affected_products,
                        str_fixing_products,
                        str_conclusion,
                        str_solution,
                        remedy_items,
                    ) = cve.make_description(
                        self.is_3rdparty_vul,
                        self.are_multiple_cveids,
                        self.releaseissue_obj["sa_title"],
                        self.analysis_obj["cweids"],
                        self.analysis_obj["cvssv3_vec"],
                        self.analysis_obj["severity_level"],
                        self.releaseissue_obj["product_data"],
                        self.releaseissue_obj["affected_products"],
                        self.releaseissue_obj["fixing_products"],
                    )
                    self.qsa_vul_description = str_vul_description
                    self.qsa_affected_products = self.releaseissue_obj[
                        "affected_products"
                    ]  # str_affected_product_names
                    self.qsa_not_affected_products = str_not_affected_products
                    self.qsa_fixing_products = str_fixing_products
                    self.qsa_conclusion = str_conclusion
                    self.qsa_solution = str_solution
                    self.qsa_remedy_items = remedy_items

                    self.description = self.qsa_vul_description + "\n"
                    # 0728 未修復產品不揭露原則
                    # self.description += str_affected_product_names + '\n'
                    if len(str_not_affected_products) > 0:
                        self.description += str_not_affected_products + "\n"
                    self.description += "\n"
                    self.description += str_solution + "\n"
                    self.solution = str_solution + "\n"
                    for remedy_item in remedy_items:
                        self.description += (
                            remedy_item["fixed_release_availability"] + "\n"
                        )
                        self.solution += (
                            remedy_item["fixed_release_availability"] + "\n"
                        )

                ### back up cve json
                backup_file = path_add_cveid + ".json.bak"
                shutil.copyfile(cve_json_file, backup_file)
                backup_cve_dict = open_json(backup_file)

                ### read json file into dict
                cve_dict = open_json(cve_json_file)
                ### Check it CVE JSON changed
                if "dataVersion" in cve_dict and (cve_dict["dataVersion"] == "5.0" or cve_dict["dataVersion"] == "5.1.0"):
                    from .json_5_0 import json_5_0

                    the_json_5_0 = json_5_0(
                        self, self._gsheet, self._qsa_id, self.summary
                    )
                    cve_dict = the_json_5_0.cve_json_complete(cve_dict)
                elif "data_version" in cve_dict and cve_dict["data_version"] == "4.0":
                    from .json_4_0 import json_4_0

                    the_json_4_0 = json_4_0(
                        self, self._gsheet, self._qsa_id, self.summary
                    )
                    cve_dict = the_json_4_0.cve_json_complete(cve_dict)
                    # backup_cve_dict['CVE_data_meta']['DATE_PUBLIC'] = cve_dict['CVE_data_meta']['DATE_PUBLIC']
                else:
                    pass
                dump_json(cve_json_file, cve_dict)
                self.output_qsa(self.analysis_obj["cweids"])

                if backup_cve_dict != cve_dict:
                    return cve_json_file  # upload the CVE JSON
                else:
                    print("無修改")
                    return None  # Don't upload
        print("有錯誤發生，不繼續流程")
        return None

    def cve_json_complete(self, cve_dict):
        cveid = self.filename
        date_public = self.task_obj["cve_publish"]
        # title = self.analysis_obj['sa_title']
        title = self.releaseissue_obj["sa_title"]
        product_data = self.releaseissue_obj["product_data"]
        url = self.task_obj["url"]
        if self.gsheet_obj:
            credit = self.gsheet_obj["credit"]
        else:
            credit = None
        qsa_id = self.qsa_id
        cweids = self.analysis_obj["cweids"]
        cvssv3_vec = self.analysis_obj["cvssv3_vec"]
        cvssv3_score = self.analysis_obj["cvssv3_score"]

        return cve_dict

    def output_qsa(self, cweids):
        from pkg._util.util_datetime import utc_to_local_str

        qsa_summary = (
            "<h3>Summary</h3>\n\n"
            "<p>{vul_description}</p>\n\n"
            # '<p>&nbsp;</p>\n'   # 0728 未修復產品不揭露原則 # '{affected_products}\n' '<p>&nbsp;</p>\n' #
            "{not_affected_products}\n"
            "<p>{solution}</p>\n"
            "{remedy_items}\n\n"
            "<p>&nbsp;</p>\n"
            "{fixing_products}\n"
            "<p>&nbsp;</p>\n"
        )
        product_2_type = {
            "QTS": "QTS",
            "QuTS hero": "QTS",
            "QuTScloud": "QTS",
            "QVP (QVR Pro appliances)": "QVP",
            "QVR": "QVR",
            "QVPN Device Client": "Utility",
            "QVPN Windows": "Utility",
            "QVR Pro Client": "Utility",
            "Container Station": "QPKG",
            "Multimedia Console": "QPKG",
            "Music Station": "QPKG",
            "QuMagie": "QPKG",
            "Video Station": "QPKG",
            "QUSBCam2": "QPKG",
            "QcalAgent": "QPKG",
            "QuFirewall": "QPKG",
            "Photo Station": "QPKG",
            "Media Streaming add-on": "QPKG",
            "Qsync Central": "QPKG",
            "Network & Virtual Switch": "QPKG",
            "QES": "QES",
            "myQNAPcloud": "QPKG",
            "QuMagie Mobile for Android": "MobileApp",
            "Proxy Server": "QPKG",
            "myQNAPcloud Link": "QPKG",
            "Notes Station 3": "QPKG",
        }
        qsa_recommendations = {
            "QTS": (
                "<h3>Recommendation</h3>\n"
                '<p>To secure your device, we recommend regularly updating your system to the latest version to benefit from vulnerability fixes. You can check the&nbsp;<a href="https://www.qnap.com/en/product/eol.php">product support status</a>&nbsp;to see the latest updates available to your NAS model.{mitigation}</p>\n'
                "<p>&nbsp;</p>\n"
                "<p><strong>Updating QTS, QuTS hero, or QuTScloud</strong></p>\n"
                "<ol>\n"
                "  <li>Log in to QTS, QuTS hero, or QuTScloud as an administrator.</li>\n"
                "  <li>Go to&nbsp;<strong>Control Panel</strong>&nbsp;&gt;&nbsp;<strong>System</strong>&nbsp;&gt;<strong>&nbsp;Firmware Update</strong>.</li>\n"
                "  <li>Under&nbsp;<strong>Live Update</strong>, click&nbsp;<strong>Check for Update</strong>.<br />\n"
                "      The system downloads and installs the latest available update.</li>\n"
                "</ol>\n"
                "<p><strong>Tip:&nbsp;</strong>You can also download the update from the QNAP website. Go to&nbsp;<strong>Support</strong>&nbsp;&gt;<strong>&nbsp;Download Center</strong>&nbsp;and then perform a manual update for your specific device.</p>\n"
                "<p>&nbsp;</p>\n"
            ),
            "QES": (
                "<h3>Recommendation</h3>\n"
                "<p>To fix these vulnerabilities, we recommend updating QES to the latest version.</p>\n"
                "<p><strong>Installing the QES Update</strong></p>\n"
                "<ol>\n"
                "  <li>Log on to QES as administrator.</li>\n"
                "  <li>Go to <strong>Control Panel</strong> &gt; <strong>System</strong> &gt;<strong> Firmware Update</strong>.</li>\n"
                "  <li>Under <strong>Live Update</strong>, click <strong>Check for Update</strong>.<br />\n"
                "      QES downloads and installs the latest available update.</li>\n"
                "</ol>\n"
                "<p><strong>Tip: </strong>You can also download the update from the QNAP website. Go to <strong>Support</strong> &gt;<strong> Download Center</strong> and then perform a manual update for your specific device.</p>"
            ),
            "QVR": (
                "<h3>Recommendation</h3>\n"
                '<p>To secure your device, we recommend regularly updating your system to the latest version to benefit from vulnerability fixes. You can check the&nbsp;<a href="https://www.qnap.com/en/product/eol.php">product support status</a>&nbsp;to see the latest updates available to your NAS model.{mitigation}</p>\n'
                "<p>&nbsp;</p>\n"
                "<p><strong>Updating QVR</strong></p>\n"
                "<ol>\n"
                "	<li>Log on to QVR as administrator.</li>\n"
                "	<li>Go to <strong>Control Panel</strong> &gt; <strong>System Settings</strong> &gt;<strong> Firmware Update</strong>.</li>\n"
                "	<li>Under <strong>Live Update</strong>, click <strong>Check for Update</strong>.<br />\n"
                "	QVR downloads and installs the latest available update.</li>\n"
                "</ol>\n"
                "<p><strong>Tip:&nbsp;</strong>You can also download the update from the QNAP website. Go to&nbsp;<strong>Support</strong>&nbsp;&gt;<strong>&nbsp;Download Center</strong>&nbsp;and then perform a manual update for your specific device.</p>\n"
                "<p>&nbsp;</p>\n"
            ),
            "QVP": (
                "<h3>Recommendation</h3>\n"
                '<p>To secure your device, we recommend regularly updating your system to the latest version to benefit from vulnerability fixes. You can check the&nbsp;<a href="https://www.qnap.com/en/product/eol.php">product support status</a>&nbsp;to see the latest updates available to your NAS model.{mitigation}</p>\n'
                "<p>&nbsp;</p>\n"
                "<p><strong>Updating QVP (QVR Pro Appliances)</strong></p>\n"
                "<ol>\n"
                "  <li>Log in to QVP as an administrator.</li>\n"
                "  <li>Go to&nbsp;<strong>Control Panel</strong>&nbsp;&gt;&nbsp;<strong>System Settings</strong>&nbsp;&gt;<strong>&nbsp;Firmware Update</strong>.</li>\n"
                "  <li>Select the&nbsp;<strong>Firmware Update</strong>&nbsp;tab.</li>\n"
                "  <li>Click&nbsp;<strong>Browse...</strong>&nbsp;to upload the latest firmware file.<br />\n"
                '      <strong>Tip:&nbsp;</strong>Download the latest firmware file for your specific device from&nbsp;<a href="https://www.qnap.com/en/download">https://www.qnap.com/go/download</a>.</li>\n'
                "  <li>Click&nbsp;<strong>Update System</strong>.<br />\n"
                "      The system installs the update.</li>\n"
                "</ol>\n\n"
            ),
            "QPKG": (
                "<h3>Recommendation</h3>\n"
                "<p>To fix the vulnerability, we recommend updating {qpkg} to the latest version.</p>\n"
                "<h3>Updating {qpkg}</h3>\n"
                "<ol>\n"
                "	<li>Log on to QTS or QuTS hero as administrator.</li>\n"
                '	<li>Open the <strong>App Center</strong> and then click <img src="https://www.qnap.com/i/_upload/support/images/magnifier.png" style="width: 18px;" /> .<br />\n'
                "	A search box appears.</li>\n"
                "	<li>Type &ldquo;{qpkg}&rdquo; and then press <strong>ENTER</strong>.<br />\n"
                "	{qpkg} appears in the search results.</li>\n"
                "	<li>Click <strong>Update</strong>.<br />\n"
                "	A confirmation message appears.<br />\n"
                "	<strong>Note:</strong> The <strong>Update</strong> button is not available if your {qpkg} is already up to date.</li>\n"
                "	<li>Click <strong>OK</strong>.<br />\n"
                "	The application is updated.</li>\n"
                "</ol>\n\n"
            ),
            "Utility": (
                "<h3>Recommendation</h3>\n\n"
                "<p>To secure your device, we recommend regularly updating your QNAP utilities to the latest versions to benefit from vulnerability fixes. "
                'You can check the <a href="https://www.qnap.com/go/utilities/" target="_blank">QNAP Utilities</a>&nbsp;page to see the latest updates available to your device operating system.{mitigation}</p>'
            ),
            "MobileApp": (
                "<h3>Recommendation</h3>\n\n"
                "<p>To secure your device, we recommend regularly updating your QNAP Android App to the latest versions to benefit from vulnerability fixes. "
                'You can check the <a href="https://www.qnap.com/en/mobile-apps" target="_blank">QNAP Mobile App</a>&nbsp;page to see the latest updates.{mitigation}</p>'
            )
        }

        str_not_affected_products = ""
        if len(self.qsa_not_affected_products) > 0:
            str_not_affected_products = "<p>{not_affected_products}</p>\n".format(
                not_affected_products=self.qsa_not_affected_products
            )
            str_not_affected_products += "<p>&nbsp;</p>"

        str_fixing_products = ""
        # 0728 未修復產品不揭露原則
        """
        if len(self.qsa_fixing_products)>0:
            str_fixing_products = '<p>{fixing_products}</p>\n<p>{conclusion}</p>'.format(fixing_products=self.qsa_fixing_products, 
                                                                                         conclusion=self.qsa_conclusion)
        """

        """
        str_remedy_items = '<ul>\n'
        for remedy_item in self.qsa_remedy_items:
            str_remedy_items += '\t<li>{remedy_item}</li>\n'.format(remedy_item=remedy_item)
        str_remedy_items += '</ul>'
        """
        str_remedy_items = (
            '<table class="table table-bordered table-hover">\n'
            '    <thead class="border-start border-end">\n'
            '        <tr class="table-light">\n'
            '            <td class="h6" width="40%">Affected Product</td>\n'
            '            <td class="h6" width="60%">Fixed Version</td>\n'
            "        </tr>\n"
            "    </thead>\n"
            '    <tbody class="border-start border-end">\n'
        )

        for remedy_item in self.qsa_remedy_items:
            str_remedy_items += (
                "        <tr>\n"
                "            <td>{product}</td>\n"
                "            <td>{remedy_item}</td>\n"
                "        </tr>\n"
            ).format(
                product=remedy_item["affected_product"],
                remedy_item=remedy_item["fixed_release_availability"],
            )
        str_remedy_items += "    </tbody>\n</table>\n"

        if self.are_multiple_cveids:
            str_vul_noun = "Vulnerabilities in "
        else:
            str_vul_noun = "Vulnerability in "

        print("----------------------------------------------------------------")
        print("Title: " + str_vul_noun + self.releaseissue_obj["sa_title"])
        print("Bulletin ID: " + self.qsa_id)
        print("CVE ID: " + self.task_obj["cveid"])

        # Affected Products
        str_affected_products = ""
        for remedy_item in self.qsa_remedy_items:
            if len(str_affected_products) > 0:
                str_affected_products += ","
            str_affected_products += remedy_item["affected_product"]
        print("Affected Products: " + str_affected_products)

        # Severity
        if "severity_level" in self.analysis_obj:
            if self.analysis_obj["severity_level"] == "[V5]":
                severity = "CRITICAL"
            elif self.analysis_obj["severity_level"] == "[V4]":
                severity = "HIGH"
            elif self.analysis_obj["severity_level"] == "[V3]":
                severity = "MEDIUM"
            elif self.analysis_obj["severity_level"] == "[V2]":
                severity = "LOW"
            else:
                severity = "NONE"
            print("Severity: " + severity)

        # Revision History
        print(
            "Revision History: <br>V1.0 ("
            + utc_to_local_str(datetime.datetime.now(), format="%B %d, %Y")
            + ") - Published "
        )

        if (
            self.gsheet_obj
            and "credit" in self.gsheet_obj
            and self.gsheet_obj["credit"]
        ):
            print("Acknowledgements: " + self.gsheet_obj["credit"])
        print("Solution: ")
        # html_qsa_affected_products = '<ul>\n' + '\t<li>' + self.qsa_affected_products + '</li>\n' + '</ul>\n'
        html_qsa_affected_products = "<ul>\n"
        for qsa_affected_product in self.qsa_affected_products:
            html_qsa_affected_products += "\t<li>" + qsa_affected_product + "</li>\n"
        html_qsa_affected_products += "</ul>\n"
        print(
            qsa_summary.format(
                vul_description=self.qsa_vul_description,
                affected_products=html_qsa_affected_products,
                not_affected_products=str_not_affected_products,
                solution=self.qsa_solution,
                remedy_items=str_remedy_items,
                fixing_products=str_fixing_products,
            )
        )
        product_names = set()
        for product in self.releaseissue_obj["affected_products"]:
            product_wo_ver = product
            import re

            # print('～～～發現產品：' + product_wo_ver)
            m = re.search(r"(\d{1,2})\.(\d{1,2})\.(\d{1,4})", product_wo_ver)
            if m and m.group(1) and m.group(2) and m.group(3):
                product_wo_ver = product_wo_ver.replace(
                    m.group(1) + "." + m.group(2) + "." + m.group(3), ""
                )
            product_wo_ver = product_wo_ver.strip()
            if product_wo_ver not in product_names:
                product_names.add(product_wo_ver)
                # print('～～～增加產品：' + product_wo_ver)
        product_name = ""
        b_print_qsa_recommendations = False
        for product_name in product_names:
            if product_name in product_2_type:
                recommendation_temp = qsa_recommendations[product_2_type[product_name]]
                if product_2_type[product_name] == "QPKG":
                    recommendation_temp = recommendation_temp.format(qpkg=product_name)
                if cweids:
                    for cweid in cweids:
                        # print('>>> CWE ID: {cweid}'.format(cweid=cweid))
                        cwe_data = cve.cweid2description(cweid)
                        if cwe_data:
                            cwe_mitigation = cwe_data["mitigation"]
                            if cwe_mitigation and len(cwe_mitigation) > 0:
                                print(
                                    recommendation_temp.format(
                                        mitigation=cwe_mitigation
                                    )
                                )
                                b_print_qsa_recommendations = True
                                break
        if not b_print_qsa_recommendations:
            if product_name in product_2_type:
                recommendation_temp = qsa_recommendations[product_2_type[product_name]]
                if product_2_type[product_name] == "QPKG":
                    recommendation_temp = recommendation_temp.format(qpkg=product_name)
                print(recommendation_temp.format(mitigation=""))
            else:
                print(
                    "!!! {product} RECOMMENDATION NOT FOUND".format(
                        product=product_name
                    )
                )

        print("----------------------------------------------------------------")

    @staticmethod
    def is_cve_json_filename(filename):
        # CVE regular expression
        cve_pattern = r"^CVE-\d{4}-\d{4,7}.json$"
        is_cve = re.match(cve_pattern, filename)
        return is_cve

    @staticmethod
    def is_cve_x_json_filename(filename):
        cve_x_pattern = r"^CVE-\d{4}-\d{4,7}(.x)+.json$"
        is_cve_x = re.match(cve_x_pattern, filename)
        return is_cve_x

    @staticmethod
    def is_qsa_json_filename(filename):
        # QSA regular expression
        qsa_pattern = r"^QSA-\d{2}-\d{2}.json$"
        is_qsa = re.match(qsa_pattern, filename)
        return is_qsa

    @staticmethod
    def is_qsa_x_json_filename(filename):
        qsa_x_pattern = r"^CVE-\d{2}-\d{2}(.x)+.json$"
        is_qsa_x = re.match(qsa_x_pattern, filename)
        return is_qsa_x

    @staticmethod
    def check_product(product, products_list, origin_term, new_term):
        products_list = ["QTS", "QuTS hero", "QuTScloud"]
        for item in products_list:
            if product.find(item) >= 0:
                return new_term
        return origin_term

    @staticmethod
    def make_product_status_statements(
        product_data, affected_products, fixing_products
    ):
        str_affected_product_names = ""
        str_yours = str_affected = "product"
        str_devices = "QNAP devices"
        for product_name in affected_products:
            if product_name and len(product_name) > 0:
                if len(str_affected_product_names) > 0:
                    str_affected_product_names += ", "
                str_affected_product_names += product_name
                str_yours = str_affected = cve.check_product(
                    product_name,
                    ["QTS", "QuTS hero", "QuTScloud"],
                    str_affected,
                    "QNAP operating system",
                )
                if product_name in ["QVPN Device Client"]:
                    str_devices = "devices running " + product_name
        if str_affected_product_names.find(",") >= 0:
            str_affected = "several " + str_affected + " versions"
        elif len(affected_products) == 1:
            str_affected = affected_products[0]

        str_fixing_product_names = ""
        for product_name in fixing_products:
            if product_name and len(product_name) > 0:
                if len(str_fixing_product_names) > 0:
                    str_fixing_product_names += ", "
                str_fixing_product_names += product_name

        str_fixed_product_names = ""
        str_not_affected_product_names = ""
        for product in product_data:
            b_not_affected = True
            for item in product["version"]["version_data"]:
                if item["version_affected"] != "x":
                    if product["product_name"] and len(product["product_name"]) > 0:
                        if len(str_fixed_product_names) > 0:
                            str_fixed_product_names += ", "
                        str_fixed_product_names += product["product_name"]
                        b_not_affected = False
                        break
            if b_not_affected:
                if product["product_name"] and len(product["product_name"]) > 0:
                    if len(str_not_affected_product_names) > 0:
                        str_not_affected_product_names += ", "
                    str_not_affected_product_names += product["product_name"]
        return (
            str_not_affected_product_names,
            str_affected_product_names,
            str_fixed_product_names,
            str_fixing_product_names,
            str_affected,
            str_yours,
            str_devices,
        )

    @staticmethod
    def make_description(
        b_3rdparty_vul,
        b_multiple_cveid,
        str_the_component,
        cweids,
        cvssv3_vec,
        severity_level,
        product_data,
        affected_products,
        fixing_products,
    ):
        (
            str_not_affected_product_names,
            str_affected_product_names,
            str_fixed_product_names,
            str_fixing_product_names,
            str_affected,
            str_yours,
            str_devices,
        ) = cve.make_product_status_statements(
            product_data, affected_products, fixing_products
        )

        if b_3rdparty_vul:
            if b_multiple_cveid:
                str_noun_n_verb = "Multiple vulnerabilities have been"
            else:
                str_noun_n_verb = "A vulnerability has been"
            str_vul_description = "{str_noun_n_verb} reported in {component}.".format(
                str_noun_n_verb=str_noun_n_verb, component=str_the_component
            )
        else:
            cweid = None
            cwe_detail = ""
            if cvssv3_vec:
                str_remote_authenticated, str_vectors = cve.remote_authenticated(
                    cvssv3_vec
                )
            else:
                str_remote_authenticated = ""
                str_vectors = "unspecified vectors"
            if cweids:
                for cweid in cweids:
                    # print('>>> CWE ID: {cweid}'.format(cweid=cweid))
                    cwe_data = cve.cweid2description(cweid)
                    if cwe_data:
                        cwe_description = cwe_data["description"]
                        if cwe_description:
                            cwe_detail = cwe_description.format(
                                affected=str_affected,
                                device=str_devices,
                                remote_authenticated=str_remote_authenticated,
                                str_vectors=str_vectors,
                            )
                        break
            str_vul_description = cwe_detail

        if b_multiple_cveid:
            str_noun_n_verb = "These vulnerabilities affect"
        else:
            str_noun_n_verb = "The vulnerability affects"
        # 0728 未修復產品不揭露原則
        # str_vul_description += ' {str_noun_n_verb} the following {str_affected}:'.format(str_noun_n_verb=str_noun_n_verb, str_affected=str_affected)

        str_not_affected_products = ""
        if len(str_not_affected_product_names) > 0:
            if str_not_affected_product_names.find(",") >= 0:
                be = "are"
            else:
                be = "is"
            str_not_affected_products = "{product_name} {be} not affected.".format(
                product_name=str_not_affected_product_names, be=be
            )

        str_fixing_products = ""

        if b_multiple_cveid:
            str_vul_noun = "the vulnerabilities"
        else:
            str_vul_noun = "the vulnerability"
        if len(str_fixing_product_names) > 0:
            urgently = ""
            if severity_level in ["[V4]", "[V5]"]:
                urgently = "urgently "
            # 0728 未修復產品不揭露原則
            # str_fixing_products = 'QNAP is {urgently}fixing {vul_noun} in {product_name}.'.format(urgently=urgently, vul_noun=str_vul_noun, product_name=str_fixing_product_names)
        # 0728 未修復產品不揭露原則
        # str_conclusion = 'Please check this security advisory regularly for updates and promptly update your {str_yours} to the latest version as soon as it is available.'.format(str_yours=str_yours)
        str_conclusion = ""

        remedy_items = []
        for product in product_data:
            if product["product_name"] is None:
                continue
            version_data = product["version"]["version_data"]
            for pf_pt_ver in version_data:
                if pf_pt_ver["version_affected"] == "x":
                    continue
                if (
                    "platform" not in pf_pt_ver
                    or pf_pt_ver["platform"] is None
                    or len(pf_pt_ver["platform"]) == 0
                ):
                    remedy_item = {
                        "affected_product": product["product_name"]
                        + " "
                        + pf_pt_ver["version_begin"],
                        "fixed_release_availability": "{product_name} {version} and later".format(
                            product_name=product["product_name"],
                            version=pf_pt_ver["version_value"],
                        ),
                    }
                else:
                    remedy_item = {
                        "affected_product": product["product_name"]
                        + " "
                        + pf_pt_ver["version_begin"],
                        "fixed_release_availability": "{platform}: {product_name} {version} and later".format(
                            platform=pf_pt_ver["platform"],
                            product_name=product["product_name"],
                            version=pf_pt_ver["version_value"],
                        ),
                    }
                remedy_items.append(remedy_item)

        if b_multiple_cveid:
            str_vul_noun = "the vulnerabilities"
        else:
            str_vul_noun = "the vulnerability"
        if len(remedy_items) > 1:
            str_remedy_noun = "versions"
        else:
            str_remedy_noun = "version"
        str_solution = "We have already fixed {str_vul_noun} in the following {str_remedy_noun}:".format(
            str_vul_noun=str_vul_noun, str_remedy_noun=str_remedy_noun
        )

        return (
            str_vul_description,
            str_affected_product_names,
            str_not_affected_products,
            str_fixing_products,
            str_conclusion,
            str_solution,
            remedy_items,
        )

    @staticmethod
    def remote_authenticated(cvssv3_vec):
        from pkg._qjira.description import extract_cvssv3_attr, extract_cvssv4_attr

        str_remote_authenticated = ""
        str_vectors = "unspecified vectors"

        av, ac, pr, ui, s, c, i, a = extract_cvssv3_attr(cvssv3_vec)
        if av == None or pr == None:
            av, ac, at, pr, ui, vc, vi, va, sc, si, sa, e = extract_cvssv4_attr(cvssv3_vec)

        if av == "N":  # 'NETWORK'
            str_remote_authenticated = ""
            str_vectors = "a network"
        elif av == "A":  # 'ADJACENT_NETWORK'
            str_remote_authenticated = "local network "
        elif av == "L":  # 'LOCAL'
            str_remote_authenticated = "local "
        else:  # 'PHYSICAL'
            str_remote_authenticated = "physical access "

        if pr == "N":  # 'NONE'
            str_remote_authenticated += "users"
        elif pr == "L":  # 'LOW'
            str_remote_authenticated += "authenticated users"
        else:  # 'HIGH'
            str_remote_authenticated += "authenticated administrators"

        return str_remote_authenticated, str_vectors

    @staticmethod
    def cvss(cvssv3_vec, cvssv3_score):
        from pkg._qjira.description import extract_cvssv3_attr, extract_cvssv4_attr

        cvss = {}
        if cvssv3_vec:
            av, ac, pr, ui, s, c, i, a = extract_cvssv3_attr(cvssv3_vec)
            if av and ac:
                cvss["vectorString"] = cvssv3_vec
                cvss["version"] = "3.1"

                if av == "N":
                    cvss["attackVector"] = "NETWORK"
                elif av == "A":
                    cvss["attackVector"] = "ADJACENT_NETWORK"
                elif av == "L":
                    cvss["attackVector"] = "LOCAL"
                else:
                    cvss["attackVector"] = "PHYSICAL"

                if ac == "L":
                    cvss["attackComplexity"] = "LOW"
                else:
                    cvss["attackComplexity"] = "HIGH"

                if pr == "N":
                    cvss["privilegesRequired"] = "NONE"
                elif pr == "L":
                    cvss["privilegesRequired"] = "LOW"
                else:
                    cvss["privilegesRequired"] = "HIGH"

                if ui == "N":
                    cvss["userInteraction"] = "NONE"
                else:
                    cvss["userInteraction"] = "REQUIRED"

                if s == "C":
                    cvss["scope"] = "CHANGED"
                else:
                    cvss["scope"] = "UNCHANGED"

                if c == "H":
                    cvss["confidentialityImpact"] = "HIGH"
                elif c == "L":
                    cvss["confidentialityImpact"] = "LOW"
                else:
                    cvss["confidentialityImpact"] = "NONE"

                if i == "H":
                    cvss["integrityImpact"] = "HIGH"
                elif i == "L":
                    cvss["integrityImpact"] = "LOW"
                else:
                    cvss["integrityImpact"] = "NONE"

                if a == "H":
                    cvss["availabilityImpact"] = "HIGH"
                elif a == "L":
                    cvss["availabilityImpact"] = "LOW"
                else:
                    cvss["availabilityImpact"] = "NONE"
            else:
                av, ac, at, pr, ui, vc, vi, va, sc, si, sa, e = extract_cvssv4_attr(cvssv3_vec)
                cvss["vectorString"] = cvssv3_vec
                cvss["version"] = "4.0"

                if av == "N":
                    cvss["attackVector"] = "NETWORK"
                elif av == "A":
                    cvss["attackVector"] = "ADJACENT_NETWORK"
                elif av == "L":
                    cvss["attackVector"] = "LOCAL"
                else:
                    cvss["attackVector"] = "PHYSICAL"

                if ac == "L":
                    cvss["attackComplexity"] = "LOW"
                else:
                    cvss["attackComplexity"] = "HIGH"

                if at == "N":
                    cvss["attackRequirements"] = "NONE"
                else:
                    cvss["attackRequirements"] = "PRESENT"

                if pr == "N":
                    cvss["privilegesRequired"] = "NONE"
                elif pr == "L":
                    cvss["privilegesRequired"] = "LOW"
                else:
                    cvss["privilegesRequired"] = "HIGH"

                if ui == "N":
                    cvss["userInteraction"] = "NONE"
                elif ui == "P":
                    cvss["userInteraction"] = "PASSIVE"
                else:
                    cvss["userInteraction"] = "ACTIVE"

                if vc == "H":
                    cvss["vulnConfidentialityImpact"] = "HIGH"
                elif vc == "L":
                    cvss["vulnConfidentialityImpact"] = "LOW"
                else:
                    cvss["vulnConfidentialityImpact"] = "NONE"

                if vi == "H":
                    cvss["vulnIntegrityImpact"] = "HIGH"
                elif vi == "L":
                    cvss["vulnIntegrityImpact"] = "LOW"
                else:
                    cvss["vulnIntegrityImpact"] = "NONE"

                if va == "H":
                    cvss["vulnAvailabilityImpact"] = "HIGH"
                elif va == "L":
                    cvss["vulnAvailabilityImpact"] = "LOW"
                else:
                    cvss["vulnAvailabilityImpact"] = "NONE"

                if sc == "H":
                    cvss["subConfidentialityImpact"] = "HIGH"
                elif sc == "L":
                    cvss["subConfidentialityImpact"] = "LOW"
                else:
                    cvss["subConfidentialityImpact"] = "NONE"

                if si == "H":
                    cvss["subIntegrityImpact"] = "HIGH"
                elif si == "L":
                    cvss["subIntegrityImpact"] = "LOW"
                else:
                    cvss["subIntegrityImpact"] = "NONE"

                if sa == "H":
                    cvss["subAvailabilityImpact"] = "HIGH"
                elif sa == "L":
                    cvss["subAvailabilityImpact"] = "LOW"
                else:
                    cvss["subAvailabilityImpact"] = "NONE"

                if e == "X":
                    cvss["exploitMaturity"] = "NOT_DEFINED"
                elif e == "A":
                    cvss["exploitMaturity"] = "ATTACKED"
                elif e == "P":
                    cvss["exploitMaturity"] = "PROOF_OF_CONCEPT"
                else:
                    cvss["exploitMaturity"] = "UNREPORTED"

        if cvssv3_score:
            base_score = float(cvssv3_score)
            cvss["baseScore"] = base_score
            if base_score <= 10.0 and base_score >= 9.0:
                cvss["baseSeverity"] = "CRITICAL"
            elif base_score <= 8.9 and base_score >= 7.0:
                cvss["baseSeverity"] = "HIGH"
            elif base_score <= 6.9 and base_score >= 4.0:
                cvss["baseSeverity"] = "MEDIUM"
            elif base_score <= 3.9 and base_score >= 0.1:
                cvss["baseSeverity"] = "LOW"
            else:
                cvss["baseSeverity"] = "NONE"

        return cvss

    @staticmethod
    def cweid2description(cweid):
        """not recommended ones
        More specific CWE option available

            CWE-20
            CWE-77
            CWE-80
            CWE-120 -> CWE-787
            CWE-259 -> CWE-922
            CWE-284 -> CWE-22
            CWE-285 -> CWE-863
            CWE-311
            CWE-522
            CWE-755
            CWE-798
            CWE-943

        CWE from CNA not within 1003 View
            CWE-73
            CWE-284 -> CWE-863
            CWE-749
            CWE-943
        """
        cweid_description = {
            "CWE-22": {
                "description": "A path traversal vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to read the contents of unexpected files and expose sensitive data via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-59": {
                "description": "A link following vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to traverse the file system to unintended locations and read or overwrite the contents of unexpected files via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-74": {
                "description": "An injection vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to execute commands via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-78": {
                "description": "An OS command injection vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to execute commands via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-79": {
                "description": "A cross-site scripting (XSS) vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to inject malicious code via {str_vectors}.",
                "mitigation": " In addition, for online activities, it's recommended to access the web through secure and trusted networks.",
            },
            "CWE-89": {
                "description": "A SQL injection vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to inject malicious code via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-120": {
                "description": "A buffer copy without checking size of input vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to execute code via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-121": {
                "description": "A stack-based buffer overflow vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to execute code via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-122": {
                "description": "A heap-based buffer overflow vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to execute code via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-125": {
                "description": "An out-of-bounds read vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to get secret values via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-190": {
                "description": "An integer overflow or wraparound vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to compromise the security of the system via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-200": {
                "description": "An exposure of sensitive information vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to compromise the security of the system via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-252": {
                "description": "An unchecked return value vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to place the system in a state that could lead to a crash or other unintended behaviors via {str_vectors}.",
                "mitigation": "",
            },
            # "CWE-284":        "An improper access control vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to compromise the security of the operating system via {str_vectors}.",
            "CWE-285": {
                "description": "An improper authorization vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to bypass intended access restrictions via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-287": {
                "description": "An improper authentication vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to compromise the security of the system via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-306": {
                "description": "A missing authentication for critical function vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to gain access to and execute certain functions via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-319": {
                "description": "A cleartext transmission of sensitive information vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to read sensitive data via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-326": {
                "description": "An inadequate encryption strength vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to decrypt the data using brute force attacks via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-331": {
                "description": "An insufficient entropy vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to predict secret via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-352": {
                "description": "A cross-site request forgery (CSRF) vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to inject malicious code via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-400": {
                "description": "An uncontrolled resource consumption vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to launch a denial-of-service (DoS) attack via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-401": {
                "description": "A missing release of memory after effective lifetime vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to launch a denial of service attack via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-427": {
                "description": "An insecure library loading vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to execute code through insecure library loading via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-428": {
                "description": "An unquoted search path or element vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to execute unauthorized code or commands via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-476": {
                "description": "A NULL pointer dereference vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to launch a denial-of-service (DoS) attack via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-522": {
                "description": "An insufficiently protected credentials vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to gain access to user accounts and the sensitive data they use via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-532": {
                "description": "An insertion of sensitive information into Log file vulnerability has been reported to affect {affected}. If exploited, the vulnerability possibly provides {remote_authenticated} with an additional, less-protected path to acquiring the information via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-601": {
                "description": "An open redirect vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to redirect users to an untrusted page that contains malwar via {str_vectors}e.",
            },
            "CWE-732": {
                "description": "An incorrect permission assignment for critical resource vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to read or modify the resource via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-787": {
                "description": "An out-of-bounds write vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to execute code via {str_vectors}.",
                "mitigation": "",
            },
            # "CWE-798":        "An insecure storage of sensitive information vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to read sensitive information by accessing the unrestricted storage mechanism via {str_vectors}.",
            "CWE-862": {
                "description": "A missing authorization vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to access data or perform actions that they should not be allowed to perform via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-863": {
                "description": "An incorrect authorization vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to bypass intended access restrictions via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-918": {
                "description": "A server-side request forgery (SSRF) vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to read application data via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-922": {
                "description": "An insecure storage of sensitive information vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to read sensitive information by accessing the unrestricted storage mechanism via {str_vectors}.",
                "mitigation": "",
            },
            "CWE-1321": {
                "description": "A prototype pollution vulnerability has been reported to affect {affected}. If exploited, the vulnerability could allow {remote_authenticated} to override existing attributes with ones that have incompatible type, which may lead to a crash via {str_vectors}.",
                "mitigation": "",
            },
        }
        if cweid in cweid_description:
            return cweid_description[cweid]
        return None
