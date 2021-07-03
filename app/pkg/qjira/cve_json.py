#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2021-06-26
#
import datetime, re

def is_cve_json_filename(filename):
    # CVE regular expression
    cve_pattern = r'^CVE-\d{4}-\d{4,7}.json$'
    is_cve = re.match(cve_pattern, filename)
    return is_cve

def is_cve_x_json_filename(filename):
    cve_x_pattern = r'^CVE-\d{4}-\d{4,7}(.x)+.json$'
    is_cve_x = re.match(cve_x_pattern, filename)
    return is_cve_x

def cve_json_complete(input_file, output_file, 
                      title, product_name, version_data,
                      description, url,
                      solution, credit, qsa_id):
    from pkg.util.util_text_file import open_json, dump_json

    ### read json file into dict
    cve_dict = open_json(input_file)

    if "CVE_data_meta" not in cve_dict:
        cve_dict["CVE_data_meta"] = {}
    cve_data_meta = cve_dict["CVE_data_meta"]
    cve_data_meta["ASSIGNER"] = "security@qnap.com"
    cve_data_meta["DATE_PUBLIC"] = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.000Z")
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
        first_vendor["product"]['product_data'] = []
        first_vendor["product"]['product_data'].append(
                    {
                        "version": {
                            "version_data": []
                        }
                    })
    first_product = first_vendor["product"]['product_data'][0]

    ### product_name, version_data
    if "product_name" not in first_product:
        first_product["product_name"] = product_name
    if "version" not in first_product:
        first_product["version"] = {}
        first_product["version"]["version_data"] = []
    first_product_version_version_data = first_product["version"]["version_data"]
    first_product_version_version_data = version_data

    first_product["version"]["version_data"] = first_product_version_version_data
    first_vendor["product"]['product_data'][0] = first_product
    cve_dict["affects"]["vendor"]["vendor_data"][0] = first_vendor

    ### "description" --> "description_data" --> [0] --> "value"
    if "description" not in cve_dict:
        cve_dict["description"] = {}
    if "description_data" not in cve_dict["description"]:
        cve_dict["description"]["description_data"] = []
    if len(cve_dict["description"]["description_data"]) == 0:
        cve_dict["description"]["description_data"].append({
                    "lang": "eng",
            })
    cve_dict["description"]["description_data"][0]["value"] = description

    ### "references" --> "reference_data" --> [0] --> "url"
    if "references" not in cve_dict:
        cve_dict["references"] = {}
    if "reference_data" not in cve_dict["references"]:
        cve_dict["references"]["reference_data"] = []
    if len(cve_dict["references"]["reference_data"]) == 0:
        cve_dict["references"]["reference_data"].append({
                    "refsource": "CONFIRM",
            })
    cve_dict["references"]["reference_data"][0]["url"] = url

    ### "solution" --> [0] --> "value"
    if "solution" not in cve_dict:
        cve_dict["solution"] = []
    if len(cve_dict["solution"]) == 0:
        cve_dict["solution"].append({
                    "lang": "eng",
            })
    cve_dict["solution"][0]["value"] = solution

    ### "credit" --> [0] --> "value"
    if "credit" not in cve_dict:
        cve_dict["credit"] = []
    if len(cve_dict["credit"]) == 0:
        cve_dict["credit"].append({
                    "lang": "eng",
            })
    cve_dict["credit"][0]["value"] = credit

    ### "source" --> [0] --> "value"
    if "source" not in cve_dict:
        cve_dict["source"] = {}
    cve_dict["source"]["advisory"] = qsa_id
    cve_dict["source"]["discovery"] = "EXTERNAL"

    dump_json(output_file, cve_dict)
    
