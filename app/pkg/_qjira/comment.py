#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2021-06-05
#
from datetime import datetime
from pkg._util.util_datetime import utc_to_local_str, duration_days


###############################################################################
### common functions
def content_filter(content, filters, b_op_and=True):
    if b_op_and:
        for filter in filters:
            if type(filter) is str:
                if content.lower().find(filter.lower()) < 0:
                    return False
            elif type(filter) is list:
                b_found = content_filter(content, filter, not b_op_and)
                if not b_found:
                    return False
        return True
    for filter in filters:
        if type(filter) is str:
            if content.lower().find(filter.lower()) >= 0:
                return True
        elif type(filter) is list:
            b_found = content_filter(content, filter, not b_op_and)
            if b_found:
                return True
    return False


def description_parser(the_obj, description, created, filters, callback):
    cid = "n/a"
    author = "n/a"
    time = datetime.strptime(created, "%Y-%m-%dT%H:%M:%S.000+0800")
    body = description
    lines = body.split("\n")
    for line in lines:
        if content_filter(line, filters):
            # print("--- Analysis is DONE as {line}".format(line=line))
            callback(the_obj, cid, author, time, line)


def comment_parser(the_obj, comment, filters, callback):
    if comment.author.displayName == "PSIRT_Jira_Robot":
        return
    cid = comment.id
    author = comment.author.displayName
    time = datetime.strptime(comment.created, "%Y-%m-%dT%H:%M:%S.000+0800")
    body = comment.body
    lines = body.split("\n")
    for line in lines:
        if content_filter(line, filters):
            # print("--- Analysis is DONE as {line}".format(line=line))
            callback(the_obj, cid, author, time, line)


def gpt_chat_completion(prompt):
    if prompt is None or len(prompt) == 0:
        prompt = "你好！"
    # print("--- Prompt: --------------------------------------")
    # print(prompt)

    try:
        import os
        from openai import OpenAI

        chatgpt_key = os.environ.get("chatgpt_key")

        client = OpenAI(
            api_key=chatgpt_key,
        )

        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            model="gpt-4",
        )
        message_text = chat_completion.choices[0].message.content + "\n"
        print("--- WHITE CAP HACKER: --------------------------------------")
        print(message_text)
        return message_text

    except Exception as e:
        print("!!! 例外錯誤:", str(e))
        return None


def file_text_content(path):
    import os
    from pkg._util.util_file import (
        extract_text_from_pdf,
        extract_text_from_word,
        unzip_and_get_file_paths,
    )

    if path is None or len(path) == 0:
        return None

    # 解壓縮並找出可出抽取文字資訊的檔案
    the_files = []
    if path.lower().endswith(".zip"):
        extracted_files = unzip_and_get_file_paths(path, os.path.dirname(path))
        for extracted_file in extracted_files:
            if (
                extracted_file.lower().endswith(".txt")
                or extracted_file.lower().endswith(".py")
                or extracted_file.lower().endswith(".sh")
                or extracted_file.lower().endswith(".md")
                or extracted_file.lower().endswith(".pdf")
                or extracted_file.lower().endswith(".docx")
            ):
                the_files.append(extracted_file)
    else:
        the_files.append(path)

    # 抽出文字資訊
    the_content_in_files = ""
    for the_file in the_files:
        if (
            the_file.lower().endswith(".txt")
            or the_file.lower().endswith(".py")
            or the_file.lower().endswith(".sh")
            or the_file.lower().endswith(".md")
        ):
            with open(the_file, "r") as file:
                the_content = file.read()
                the_content_in_files += the_content[0:100000] + "\n\n"
        elif the_file.lower().endswith(".pdf"):
            the_content = extract_text_from_pdf(the_file)
            the_content_in_files += the_content[0:100000] + "\n\n"
        elif the_file.lower().endswith(".docx"):
            the_content = extract_text_from_word(path)
            the_content_in_files += the_content[0:100000] + "\n\n"

    return the_content_in_files
