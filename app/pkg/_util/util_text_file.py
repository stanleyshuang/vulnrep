#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  util 1.0
# Date:     2021-06-04
#
import json


def get_lines(filename):
    with open(filename, "r") as fp:
        all_lines = fp.readlines()
        return all_lines
    return None


def get_lines_b(filename):
    all_lines = []
    with open(filename, "rb") as fp:
        all_b_lines = fp.readlines()
        for b_line in all_b_lines:
            all_lines.append(str(b_line))
        return all_lines
    return None


def flush_text(filename, content):
    fp = open(filename, "a")  # 開啟檔案
    fp.write(content)  # 寫入 This is a testing! 到檔案
    fp.close()  # 關閉檔案


def output_text(filepath, content):
    fp = open(filepath, "w")  # 開啟檔案
    fp.write(content)  # 寫入 This is a testing! 到檔案
    fp.close()  # 關閉檔案


def open_json(filename):
    with open(filename) as data_file:
        data = json.load(data_file)
    return data


def dump_json(filename, data):
    json_str = json.dumps(data, sort_keys=True, indent=4, ensure_ascii=False)
    with open(filename, "w") as fp:
        fp.write(json_str)


def html_2_text(html_content):
    import html2text

    # Create an HTML to plain text converter
    converter = html2text.HTML2Text()
    # Convert HTML to plain text
    plain_text = converter.handle(html_content)
    return plain_text
