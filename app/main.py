#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2021-06-04
#
import json, os, sys
from jira import JIRA

from pkg._gsheet.gsheet_vulnrep import gsheet_vulnrep
from pkg._mail import i_mail
from pkg._qjira import i_issue, get_issuetype
from pkg._qjira.batch_common import jira_filter, jira_tasks_routine, jira_task_routine
from pkg._qjira.triage import triage
from pkg._qjira.bounty import researcher_reward, bounty_nomination
from pkg._qjira.qsa import qsa_publish
from pkg._qjira.comment import gpt_chat_completion, file_text_content
from pkg._qjira.description import extract_model
from pkg._qjira.task import analysis_task
from pkg._qjira.bug import vuln_bug
from pkg._qjira.releaseproc import (
    app_release_process,
    store_publish_process,
    fw_release_process,
    fw_delivery_process,
)
from pkg._qsalesforce import sf_get_data
from pkg._mantis.mantis import mantis
from pkg._sf_helper.sf_helper import (
    create_case,
    respond,
    update_reply_record,
    upload_attachments,
)
from pkg._util.util_file import create_folder
from pkg._util.util_debug import debug


def get_jira_issue(server, username, password, jira_id):
    jira = JIRA(basic_auth=(username, password), options={"server": server})
    return jira, jira.issue(jira_id, expand="changelog")


def get_mantis_ticket(mantis_url, username, password, project, mantis_id, downloads):
    return mantis(mantis_url, username, password, project, mantis_id, downloads)


def jira_subtask(jira, the_issue, b_update, group_name="n/a"):
    matrixcup = [
        {"name": "QTS研發處/軟體研發一部 61110", "manager": "WadeLiu@qnap.com"},
        {"name": "QTS研發處/軟體研發二部 61120", "manager": "AquavitWu@qnap.com"},
        {"name": "視訊產品研發處/軟體研發六部 61760", "manager": "WCLin@qnap.com"},
        {"name": "視訊產品研發處/軟體研發三部 61730", "manager": "JustinTseng@qnap.com"},
        {"name": "視訊產品研發處/軟體研發一部 61710", "manager": "BruceLan@qnap.com"},
        {"name": "先進網路產品研發處/軟體研發四部 65240", "manager": "GaryHuang@qnap.com"},
        {"name": "視訊產品研發處/軟體研發七部 61770", "manager": "ArcherChang@qnap.com"},
        {"name": "系統產品研發處/系統研發一部 63130", "manager": "KevinKo@qnap.com"},
        {"name": "雲端與邊際運算研發處/軟體研發一部 61510", "manager": "AnryLu@qnap.com"},
    ]
    divisions = [
        {"name": "系統核心研發處 33100", "manager": "CHYang@qnap.com"},
        {"name": "QTS研發處 61100", "manager": "KenChen@qnap.com"},
        {"name": "儲存產品研發處 61200", "manager": "IvanChen@qnap.com"},
        {"name": "雲端與邊際運算研發處 61500", "manager": "HarryChen@qnap.com"},
        {"name": "視訊產品研發處 61700", "manager": "ChardChen@qnap.com"},
        {"name": "系統軟體研發處 63100", "manager": "NikeChen@qnap.com"},
        {"name": "先進網路產品研發處 65200", "manager": "JimHsiao@qnap.com"},
        {"name": "資料智能應用研發處 68000", "manager": "PeterChiu@qnap.com"},
    ]
    mobile_apps = [
        {"name": "QTS研發處/軟體研發三部 61130", "manager": "BenLin@qnap.com"},
        {"name": "QTS研發處/軟體研發五部 61150", "manager": "JohnsonLee@qnap.com"},
        {
            "name": "先進網路產品研發處/軟體研發四部 65240",
            "manager": "GaryHuang@qnap.com",
        },
    ]
    special = [
        {
            "name": "企業儲存產品研發處/軟體研發六部 61360",
            "manager": "JeffHsueh@qnap.com",
        },
    ]
    qpkgs = [
        {"name": "系統核心研發處/軟體研發三部 33130", "manager": "RonanLin@qnap.com"},
        {"name": "QTS研發處/軟體研發一部 61110", "manager": "JackyHsu@qnap.com"},
        {"name": "QTS研發處/軟體研發二部 61120", "manager": "AquavitWu@qnap.com"},
        {"name": "QTS研發處/軟體研發三部 61130", "manager": "BenLin@qnap.com"},
        {"name": "QTS研發處/軟體研發四部 61140", "manager": "KevinLiao@qnap.com"},
        {"name": "QTS研發處/軟體研發五部 61150", "manager": "JohnsonLee@qnap.com"},
        {"name": "雲端與邊際運算研發處 61500", "manager": "HarryChen@qnap.com"},
        {
            "name": "雲端與邊際運算研發處/軟體研發一部 61510",
            "manager": "AnryLu@qnap.com",
        },
        {
            "name": "雲端與邊際運算研發處/軟體研發三部 61530",
            "manager": "RackHo@qnap.com",
        },
        {"name": "視訊產品研發處/軟體研發一部 61710", "manager": "BruceLan@qnap.com"},
        {"name": "視訊產品研發處/軟體研發二部 61720", "manager": "JasonKuo@qnap.com"},
        {
            "name": "視訊產品研發處/軟體研發三部 61730",
            "manager": "JustinTseng@qnap.com",
        },
        {"name": "視訊產品研發處/軟體研發四部 61740", "manager": "JimmyChen@qnap.com"},
        {"name": "視訊產品研發處/軟體研發五部 61750", "manager": "LukeLei@qnap.com"},
        {"name": "視訊產品研發處/軟體研發六部 61760", "manager": "WCLin@qnap.com"},
        {
            "name": "視訊產品研發處/軟體研發七部 61770",
            "manager": "ArcherChang@qnap.com",
        },
        {"name": "視訊產品研發處/軟體研發八部 61780", "manager": "ChungyiWu@qnap.com"},
        {"name": "先進網路產品研發處/軟體研發一部 65210", "manager": "VicLi@qnap.com"},
        {
            "name": "先進網路產品研發處/軟體研發二部 65220",
            "manager": "JosephWang@qnap.com",
        },
        {
            "name": "先進網路產品研發處/軟體研發三部 65230",
            "manager": "JimHsiao@qnap.com",
        },
        {
            "name": "先進網路產品研發處/軟體研發四部 65240",
            "manager": "GaryHuang@qnap.com",
        },
        {
            "name": "先進網路產品研發處/軟體研發五部 65250",
            "manager": "CharleyCheng@qnap.com",
        },
        {
            "name": "資料智能應用研發處/軟體研發一部 68010",
            "manager": "JayZhou@qnap.com",
        },
        {"name": "資料智能應用研發處/軟體研發二部 68020", "manager": "DoroWu@qnap.com"},
        {
            "name": "資料智能應用研發處/軟體研發二部 68020",
            "manager": "MattLee@qnap.com",
        },
        {
            "name": "資料智能應用研發處/軟體研發三部 68030",
            "manager": "ZZCheng@qnap.com",
        },
        {
            "name": "企業儲存產品研發處/軟體研發ㄧ部 61310",
            "manager": "DennisYang@qnap.com",
        },
        {
            "name": "企業儲存產品研發處/軟體研發二部 61320",
            "manager": "AbulaHsu@qnap.com",
        },
        {
            "name": "企業儲存產品研發處/軟體研發三部 61330",
            "manager": "WalkerLee@qnap.com",
        },
        {
            "name": "企業儲存產品研發處/軟體研發四部 61340",
            "manager": "GeorgeWu@qnap.com",
        },
        {
            "name": "企業儲存產品研發處/軟體研發五部 61350",
            "manager": "LuciferChen@qnap.com",
        },
        {
            "name": "企業儲存產品研發處/軟體研發六部 61360",
            "manager": "JeffHsueh@qnap.com",
        },
    ]
    storage = [
        {"name": "[storage-iSCSI_&_FC]", "manager": "LuciferChen@qnap.com"},
        {"name": "[storage-VJBOD_Cloud]", "manager": "LuciferChen@qnap.com"},
        {"name": "[storage-NVS]", "manager": "LuciferChen@qnap.com"},
        {"name": "[storage-USB_Printer]", "manager": "LuciferChen@qnap.com"},
        {"name": "[storage-Control_Panel]", "manager": "GeorgeWu@qnap.com"},
    ]

    groups = {
        "divisions": divisions,
        "mobile_apps": mobile_apps,
        "qpkgs": qpkgs,
        "storage": storage,
        "special": special,
        "matrixcup": matrixcup,
    }

    if group_name not in groups:
        print("The group name not found")
        return

    issue = jira.issue(the_issue.key)
    issue_project = issue.fields.project.key
    issue_description = issue.fields.description
    issue_summary = issue.fields.summary
    print(issue_summary)
    for i in range(len(groups[group_name])):
        item = groups[group_name][i]
        jira_dict_convert = {
            "project": {"key": issue_project},
            "summary": issue_summary + " - " + item["name"],
            "assignee": {"name": item["manager"]},
            "issuetype": {"name": "Sub-task"},
            "description": issue_description,
            "parent": {"key": issue.key},
            # 'components': [{'name': 'Component'}],
            # 'customfield_12761': SomeCustomFieldValue
        }
        print("{name} @{manager}".format(name=item["name"], manager=item["manager"]))
        if b_update:
            try:
                new_issue = jira.create_issue(jira_dict_convert)
                jira_add_watchers(jira, issue, [item["manager"]], b_update)
            except Exception as e:
                print("    " + str(e))
                print("    manager: " + item["manager"])


def jira_add_watchers(jira, the_issue, watchers, b_update):
    if not b_update:
        return
    """
    watcher = jira.watchers(the_issue.issue)
    print("Issue has {} watcher(s)".format(watcher.watchCount))
    for watcher in watcher.watchers:
        print(watcher)
        print(watcher.name)
        # watcher is instance of jira.resources.User:
        print(watcher.emailAddress)
    """
    issue = jira.issue(the_issue.key)
    for watcher in watchers:
        print(
            "{issuekey} add watcher {watcher}".format(
                issuekey=issue.key, watcher=watcher
            )
        )
        try:
            jira.add_watcher(issue.id, watcher)
        except Exception as e:
            print("    " + str(e))


def task_filter(jira, jql, debugobj):
    todo_issue_keys = jira_filter(jira, jql)
    todo_task_keys = set()
    for key in todo_issue_keys:
        an_issue = jira.issue(key, expand="changelog")
        print(
            "      [{key}]{summary} - [{updated}]".format(
                key=key,
                summary=an_issue.fields.summary,
                updated=an_issue.fields.updated[11:19],
            )
        )
        if get_issuetype(an_issue) == "Task":
            todo_task_keys.add(an_issue.key)
        elif get_issuetype(an_issue) == "Bug":
            the_issue = vuln_bug(
                jira, jira.issue(an_issue.key, expand="changelog"), debugobj
            )
            the_task_issue = the_issue.find_task()
            if the_task_issue:
                print(
                    "          {bug} --> {task}".format(
                        bug=the_issue.issue.key, task=the_task_issue.key
                    )
                )
                todo_task_keys.add(the_task_issue.key)
        elif get_issuetype(an_issue) == "App Release Process":
            continue
        elif get_issuetype(an_issue) == "FW Release Process":
            continue
        elif get_issuetype(an_issue) == "FW Delivery Process":
            continue
        elif get_issuetype(an_issue) == "Store Publish Process":
            continue
        else:
            continue
    return todo_task_keys


def bug_filter(jira, jql):
    todo_issue_keys = jira_filter(jira, jql)
    todo_bug_keys = set()
    for key in todo_issue_keys:
        an_issue = jira.issue(key, expand="changelog")
        print(
            "      [{key}]{summary} - [{updated}]".format(
                key=key,
                summary=an_issue.fields.summary,
                updated=an_issue.fields.updated[11:19],
            )
        )
        if get_issuetype(an_issue) == "Task":
            continue
        elif get_issuetype(an_issue) == "Bug":
            todo_bug_keys.add(an_issue.key)
        elif get_issuetype(an_issue) == "App Release Process":
            continue
        elif get_issuetype(an_issue) == "FW Release Process":
            continue
        elif get_issuetype(an_issue) == "FW Delivery Process":
            continue
        elif get_issuetype(an_issue) == "Store Publish Process":
            continue
        else:
            continue
    return todo_bug_keys


def notes_done_close_task(jira, the_issue, gsheet):
    """
    送簽呈並關閉 Jira Task
    """
    from datetime import datetime
    from pkg._util.util_datetime import local_to_local_str

    print("   送簽呈並關閉 Task [" + the_issue.issue.key + "]")
    notes_submitted_date_str = local_to_local_str(datetime.now(), format="%Y-%m-%d")
    print("   日期: {date}".format(date=notes_submitted_date_str))
    gsheet.set_notes_submitted_date(the_issue, notes_submitted_date_str)

    if (
        "StanleySHuang@qnap.com".lower()
        == the_issue.issue.raw["fields"]["assignee"]["name"].lower()
        and "confirm / test" == the_issue.issue.fields.status.name
    ):
        # transitions = jira.transitions(the_issue.issue)
        # print([(t['id'], t['name']) for t in transitions]) # [('51', 'abort'), ('91', 'OK'), ('101', 'NG')]
        jira.transition_issue(the_issue.issue, "91")
        print("--- Update Status                        Close")
        jira.add_comment(the_issue.issue, "送簽呈並關閉。")


def usage():
    print("USAGE:  python main.py cmd --[option] --[mode]")
    print("--")
    print(
        "cmd:    jira:jira_id[:assignee],                           parse jira a case"
    )
    print(
        "                                                           jira_id:  JIRA ticket, for example, INTSI000-732"
    )
    print(
        "        researcher:email,                                  summarize the researcher's reports"
    )
    print(
        "                                                           email:  the researcher's email"
    )
    print(
        "        mantis:mitis_id,                                   parse mantis a case"
    )
    print(
        "                                                           mantis_id: Mantis ticket, for example, 88590"
    )
    print(
        "        sf.[qts|cloud|web|misc].sf_case_num,               parse SalesForce a case"
    )
    print(
        "                                                           sf_case_num: SalesForce ticket, for example, Q-202211-14070"
    )
    print(
        "        sfmsg:option:sf_case_num.[reply_record_name],      SalesForce reply messages"
    )
    print("                                                           options")
    print(
        "                                                               tech_support: redirect to technical support"
    )
    print(
        "                                                               paypal: request for PayPal account"
    )
    print(
        "                                                               info_received: contact information received"
    )
    print(
        "                                                               invalid: invalid report"
    )
    print(
        "                                                               more_info: request for more information"
    )
    print(
        "                                                               not_reproduced: request for more information"
    )
    print(
        "                                                               redundant: redundant casess"
    )
    print(
        "                                                               paid: inform paid and close"
    )
    print(
        "                                                               inquiry: use new email inquiry"
    )
    print(
        "        jiramsg:subcmd:jira_key:[assignee],                Jira issue reply messages"
    )
    print("                                                           subcmd")
    print(
        "                                                               verify: assign DQV verifying the jira issue"
    )
    print(
        "                                                               reassign: reassign an analyst"
    )
    print(
        "                                                               invalid: invalid report"
    )
    print(
        "                                                               investigate: 讀取 Jira 資訊"
    )
    print(
        "        jiraadm:subcmd:jira_key:[assignee],                Jira issue administration"
    )
    print(
        "                                                               rm_analysis: reset analysis data, so that you can redo the analysis again"
    )
    print(
        "                                                               get_finding_response: retrieve the notification mail"
    )
    print(
        "        hour:n,                                            latest [n] hour(s)"
    )
    print(
        "                                                           n: how many hour(s) backtracking, for example, 3"
    )
    print(
        "        remind:n,                                          no update for [n] day(s)"
    )
    print(
        "                                                           n: how many day(s) the issue not updated"
    )
    print(
        "        subtask:jira_id:group_name,                        create subtask for each teams"
    )
    print(
        "                                                           jira_id:     JIRA ticket"
    )
    print(
        "                                                           group_name:  divisions|mobile_apps"
    )
    print(
        "        abort:jira_id,                                     update jira a case abort"
    )
    print(
        "                                                           jira_id:  JIRA issue"
    )
    print(
        "                                                           jira_id:  JIRA issue"
    )
    print("        jira.notes:jirakey[|jirakey],                      送簽呈完成")
    print("        v5,                                                make v5 list")
    print("        unittest,                                          unit test")
    print("        test,                                              a test")
    print("        mail:subject,body,sender_email,receiver_emails,    email test")
    print(
        "        adm:rmfile:[filename],                             remove filename, for example, xreleaseproc.json, qsa.json"
    )
    print(
        "        adm:replacekey:[jirakey]:[filename]:[a]:[b],       replace key in filename, from a to b"
    )
    print(
        "        adm:inittriageack:[issuekey],                      retrieve Vulnerability Report Initial Triage Acknowledgment"
    )
    print(
        "        gpt:prompt,                                        ask ChatGPT a question"
    )
    print("        util:subcmd:path:[prompt],                         Utility command")
    print("                                                           subcmd")
    print(
        "                                                               digest: 解讀檔案並給出繁體中文摘要"
    )
    print(
        "                                                               prompt: 額外指示"
    )
    print("option: [standard | update], default is standard")
    print("mode:   [verbose | iteration | regular], default is --regular")
    print("-------------------------------------------------")
    quit()


class CommandHandler:
    def __init__(self, argv):
        self.cmd = "jira"
        self.option = "standard"
        self.mode = "regular"
        self.parse_arguments(argv)
        self.load_environment_variables()
        self.debugobj = debug(self.mode)
        self.create_folders()
        self.gsheet = gsheet_vulnrep(
            the_credential=os.environ.get("google_api_credential"),
            the_key=os.environ.get("google_sheet_key"),
            url=os.environ.get("jira_url"),
        )

    def parse_arguments(self, argv):
        for idx, arg in enumerate(argv[1:], 1):
            self.handle_argument(arg)

    def handle_argument(self, arg):
        # Example for one command; similarly handle others
        if arg in [
            "unittest",
            "test",
            "allresearchers",
            "v5",
            "triage",
            "bounty_nomination",
            "qsa",
            "rn",
            "overdue",
        ]:
            self.cmd = arg
            self.jira_key = None
        elif arg.find("jira:") >= 0:
            # cmd:jira ###########
            self.cmd = "jira"
            input_data = arg[len("jira:") :]
            if input_data.find(":") >= 0:
                inputs = input_data.split(":")
                self.jira_key = inputs[0]
                self.assignee = inputs[1]
            else:
                self.jira_key = input_data
                self.assignee = None
        elif arg.find("hour:") >= 0:
            # cmd:hour ###########
            self.cmd = "hour"
            self.hours = int(arg[len("hour:") :])
        elif arg.find("remind:") >= 0:
            # cmd:remind #########
            self.cmd = "remind"
            self.days = int(arg[len("remind:") :])
        elif arg.find("jiramsg:") >= 0:
            # cmd:jiramsg ########
            self.cmd = "jiramsg"
            tokens = arg.split(":")
            self.subcmd = tokens[1]
            print("    subcmd: " + self.subcmd)
            self.jira_key = tokens[2]
            print("    jira_key: " + self.jira_key)
            self.assignee = None
            if len(tokens) > 3:
                self.assignee = tokens[3]
                print("    assignee: " + self.assignee)
        elif arg.find("jiraadm:") >= 0:
            # cmd:jiraadm ########
            self.cmd = "jiraadm"
            tokens = arg.split(":")
            self.subcmd = tokens[1]
            print("    subcmd: " + self.subcmd)
            self.jira_key = tokens[2]
            print("    jira_key: " + self.jira_key)
            self.assignee = None
            if len(tokens) > 3:
                self.assignee = tokens[3]
                print("    assignee: " + self.assignee)
        elif arg.find("qsa:") >= 0:
            # cmd:qsa ############
            self.cmd = "qsa"
            self.jira_key = arg[len("qsa:") :]
        elif arg.find("rn:") >= 0:
            # cmd:rn #############
            self.cmd = "rn"
            self.jira_key = arg[len("rn:") :]
        elif arg.find("overdue:") >= 0:
            # cmd:overdue ########
            self.cmd = "overdue"
            self.jira_key = arg[len("overdue:") :]
        elif arg.find("triage:") >= 0:
            # cmd:triage
            self.cmd = "triage"
            self.jira_key = arg[len("triage:") :]
        elif arg.find("bounty_nomination:") >= 0:
            # cmd:bounty_nomination
            self.cmd = "bounty_nomination"
            self.jira_key = arg[len("bounty_nomination:") :]
        elif arg.find("researcher:") >= 0:
            # cmd:researcher #####
            self.cmd = "researcher"
            self.researcher_email = arg[len("researcher:") :]
        elif arg.find("mantis:") >= 0:
            # cmd:mantis #########
            self.cmd = "mantis"
            input_data = arg[len("mantis:") :]
            if input_data.find(":") >= 0:
                inputs = input_data.split(":")
                self.mantis_id = int(inputs[0].replace("#", ""))
                self.the_watcher = inputs[1]
            else:
                self.mantis_id = int(input_data.replace("#", ""))
                self.the_watcher = None
        elif arg.find("subtask:") >= 0:
            # cmd:subtask #########
            self.cmd = "subtask"
            input_data = arg[len("subtask:") :]
            if input_data.find(":") >= 0:
                inputs = input_data.split(":")
                self.jira_key = inputs[0]
                self.group_name = inputs[1]
            else:
                self.mantis_id = int(input_data)
                self.group_name = None
        elif arg.find("sf.") >= 0:
            # cmd:sf #############
            self.cmd = "sf"
            tokens = arg.split(".")
            self.product_cat = tokens[1]
            self.sf_case_num = tokens[2]
        elif arg.find("sfmsg.") >= 0:
            # cmd:sfmsg ##########
            self.cmd = "sfmsg"
            tokens = arg.split(".")
            self.subcmd = tokens[1]
            self.sf_case_num = tokens[2]
            self.reply_record_name = None
            if len(tokens) > 3:
                self.reply_record_name = tokens[3]
        elif arg.find("mail:") >= 0:
            # cmd:mail ###########
            self.cmd = "mail"
            self.mail_data = arg[len("mail:") :]
        elif arg.find("gpt:") >= 0 or arg == "gpt":
            # cmd:gpt ############
            self.cmd = "gpt"
            if arg.find("gpt:") >= 0:
                self.prompt = arg[len("gpt:") :]
            else:
                self.prompt = None
        elif arg.find("util:") >= 0:
            # cmd:util ########
            self.cmd = "util"
            tokens = arg.split(":")
            self.subcmd = tokens[1]
            print("    subcmd: " + self.subcmd)
            self.path = tokens[2]
            print("    path: " + self.path)
            self.add_prompt = None
            if len(tokens) > 3:
                self.add_prompt = tokens[3]
                print("    add_prompt: " + self.add_prompt)
        elif arg in ["--verbose", "--iteration"]:
            # mode ###############
            self.mode = arg[2:]
            print("    mode: " + self.mode)
        elif arg in ["verbose", "iteration"]:
            # mode ###############
            self.mode = arg
            print("    mode: " + self.mode)
        elif arg in ["--standard", "--update"]:
            # option #############
            self.option = arg[2:]
            print("    option: " + self.option)
        elif arg in ["standard", "update"]:
            # option #############
            self.option = arg
            print("    option: " + self.option)
        ### replace sys.argv[idx] with arg

    def load_environment_variables(self):
        # Get environment variables
        self.jira_url = os.environ.get("jira_url")
        self.jira_username = os.environ.get("jira_username")
        self.jira_password = os.environ.get("jira_password")

        self.salesforce_url = os.environ.get("salesforce_url")
        self.salesforce_username = os.environ.get("salesforce_username")
        self.salesforce_password = os.environ.get("salesforce_password")
        self.salesforce_orgid = os.environ.get("salesforce_orgid")

        self.mantis_url = os.environ.get("mantis_url")
        self.mantis_username = os.environ.get("mantis_username")
        self.mantis_password = os.environ.get("mantis_password")
        self.mantis_project = os.environ.get("mantis_project")

        self.pgp_passphrase = os.environ.get("pgp_passphrase")
        self.pgp_key_path = os.environ.get("pgp_key_path")

        self.apphome = os.environ.get("apphome")

    def create_folders(self):
        # Create data folder
        self.data = self.apphome + "/data"
        create_folder(self.data)

        # Create downloads folder
        self.downloads = self.apphome + "/downloads"
        create_folder(self.downloads)

    def execute_command(self):
        if self.cmd == "test":
            self.handle_test_command()
        elif self.cmd == "jira":
            self.handle_jira_command()
        elif self.cmd == "hour":
            self.handle_hour_command()
        elif self.cmd == "remind":
            self.handle_remind_command()
        elif self.cmd == "jiramsg":
            self.handle_jiramsg_command()
        elif self.cmd == "jiraadm":
            self.handle_jiraadm_command()
        elif self.cmd == "qsa":
            self.handle_qsa_command()
        elif self.cmd == "rn":
            self.handle_rn_command()
        elif self.cmd == "v5":
            self.handle_v5_command()
        elif self.cmd == "overdue":
            self.handle_overdue_command()
        elif self.cmd == "triage":
            self.handle_triage_command()
        elif self.cmd == "bounty_nomination":
            self.handle_bounty_nomination_command()
        elif self.cmd == "researcher":
            self.handle_researcher_command()
        elif self.cmd == "mantis":
            self.handle_mantis_command()
        elif self.cmd == "subtask":
            self.handle_subtask_command()
        elif (
            self.cmd == "sf"
            and self.product_cat
            and len(self.product_cat) > 0
            and self.sf_case_num
            and len(self.sf_case_num) > 0
        ):
            create_case(
                self.product_cat,
                self.sf_case_num,
                self.salesforce_orgid,
                self.salesforce_username,
                self.salesforce_password,
                self.jira_username,
                self.jira_password,
                self.jira_url,
                self.data,
                self.downloads,
                self.pgp_passphrase,
                self.pgp_key_path,
                self.debugobj,
            )
        elif (
            self.cmd == "sfmsg"
            and self.subcmd
            and len(self.subcmd) > 0
            and self.sf_case_num
            and len(self.sf_case_num) > 0
        ):
            if self.subcmd == "reply_record":
                update_reply_record(
                    self.sf_case_num,
                    self.salesforce_orgid,
                    self.salesforce_username,
                    self.salesforce_password,
                    self.reply_record_name,
                    self.jira_username,
                    self.jira_password,
                    self.jira_url,
                    self.data,
                    self.downloads,
                    self.pgp_passphrase,
                    self.pgp_key_path,
                    self.debugobj,
                )
                upload_attachments(
                    self.sf_case_num,
                    self.salesforce_orgid,
                    self.salesforce_username,
                    self.salesforce_password,
                    self.jira_username,
                    self.jira_password,
                    self.jira_url,
                    self.data,
                    self.downloads,
                    self.pgp_passphrase,
                    self.pgp_key_path,
                    self.debugobj,
                )
            else:
                respond(
                    self.subcmd,
                    self.sf_case_num,
                    self.salesforce_orgid,
                    self.salesforce_username,
                    self.salesforce_password,
                    self.data,
                    self.downloads,
                    self.pgp_passphrase,
                    self.pgp_key_path,
                    self.debugobj,
                    self.reply_record_name,
                )
        elif self.cmd == "mail":
            self.handle_mail_command()
        elif self.cmd == "unittest":
            self.handle_unittest_command()

    def handle_test_command(self):
        pass

    def handle_jira_command(self):
        if not self.jira_key or len(self.jira_key) == 0:
            quit()
        jira, issue = get_jira_issue(
            self.jira_url, self.jira_username, self.jira_password, self.jira_key
        )
        b_update = self.option == "update"
        if get_issuetype(issue) == "Task":
            the_issue = analysis_task(jira, issue, self.debugobj)
            jira_task_routine(
                the_issue,
                self.salesforce_orgid,
                self.salesforce_username,
                self.salesforce_password,
                self.data,
                self.downloads,
                self.option,
                self.gsheet,
                self.assignee,
            )
        elif get_issuetype(issue) == "Bug":
            the_issue = vuln_bug(jira, issue, self.debugobj)
            the_task_issue = the_issue.find_task()
            if the_task_issue:
                the_task_issue = analysis_task(jira, the_task_issue, self.debugobj)
                jira_task_routine(
                    the_task_issue,
                    self.salesforce_orgid,
                    self.salesforce_username,
                    self.salesforce_password,
                    self.data,
                    self.downloads,
                    self.option,
                    self.gsheet,
                    self.assignee,
                )
            # bug_raw, release_raws = the_issue.check(the_issue, the_issue, data, downloads, b_update=b_update)
        elif get_issuetype(issue) == "App Release Process":
            the_issue = app_release_process(jira, issue, self.debugobj)
            release_raws = the_issue.check(
                the_issue, the_issue, self.data, self.downloads, b_update=b_update
            )
        elif get_issuetype(issue) == "FW Release Process":
            the_issue = fw_release_process(jira, issue, self.debugobj)
            release_raws = the_issue.check(
                the_issue, the_issue, self.data, self.downloads, b_update=b_update
            )
        elif get_issuetype(issue) == "FW Delivery Process":
            the_issue = fw_delivery_process(jira, issue, self.debugobj)
            release_raw = the_issue.check(
                the_issue, the_issue, self.data, self.downloads, b_update=b_update
            )
        elif get_issuetype(issue) == "Store Publish Process":
            the_issue = store_publish_process(jira, issue, self.debugobj)
            release_raw = the_issue.check(
                the_issue, the_issue, self.data, self.downloads, b_update=b_update
            )
        elif get_issuetype(issue) == "Sub-task":
            the_issue = analysis_task(jira, issue, self.debugobj)
        else:
            quit()

        if the_issue and self.mode == "verbose":
            the_issue.dump()

    def handle_hour_command(self):
        jira = JIRA(
            basic_auth=(self.jira_username, self.jira_password),
            options={"server": self.jira_url},
        )
        jql = "component=vulnerability_report and updated <= -0h and updated > -{upperbound}h order by key desc".format(
            upperbound=self.hours
        )
        todo_task_keys = task_filter(jira, jql, self.debugobj)
        researcher_emails = set()
        for key in todo_task_keys:
            the_issue = analysis_task(
                jira, jira.issue(key, expand="changelog"), self.debugobj
            )
            researcher_email = jira_task_routine(
                the_issue,
                self.salesforce_orgid,
                self.salesforce_username,
                self.salesforce_password,
                self.data,
                self.downloads,
                self.option,
                self.gsheet,
                None,
            )
            if researcher_email:
                researcher_emails.add(researcher_email)
        for researcher_email in researcher_emails:
            subject = researcher_email
            jql = 'project=INTSI000 and type=Task and component=vulnerability_report and TEXT ~ "{researcher_email}" order by key desc'.format(
                researcher_email=researcher_email
            )
            all_outputs = researcher_reward(
                jira,
                jql,
                self.gsheet,
                self.salesforce_orgid,
                self.salesforce_username,
                self.salesforce_password,
                self.data,
                self.downloads,
                debugobj=self.debugobj,
                researcher_email=researcher_email,
            )
            body = all_outputs[researcher_email]
            mail = i_mail(subject, body)
            mail.send()

    def handle_remind_command(self):
        jira = JIRA(
            basic_auth=(self.jira_username, self.jira_password),
            options={"server": self.jira_url},
        )
        assignees = {}
        jql_task_no_updated = "component = vulnerability_report and type = Task and resolution = Unresolved and updated <= -{lowerbound}d order by key desc".format(
            lowerbound=self.days
        )
        todo_task_keys = task_filter(jira, jql_task_no_updated, self.debugobj)
        for key in todo_task_keys:
            the_issue = analysis_task(
                jira, jira.issue(key, expand="changelog"), self.debugobj
            )
            if the_issue.issue.fields.assignee.emailAddress not in assignees:
                assignee = {"name": the_issue.issue.fields.assignee.name, "issues": {}}
                assignees[the_issue.issue.fields.assignee.emailAddress] = assignee
            else:
                assignee = assignees[the_issue.issue.fields.assignee.emailAddress]
            issues = assignee["issues"]
            issues[key] = the_issue.issue.fields.summary

        jql_bug_no_updated = "component = vulnerability_report and type = Bug and resolution = Unresolved and updated <= -{lowerbound}d order by key desc".format(
            lowerbound=self.days
        )
        todo_bug_keys = bug_filter(jira, jql_bug_no_updated)
        for key in todo_bug_keys:
            the_issue = vuln_bug(
                jira, jira.issue(key, expand="changelog"), self.debugobj
            )
            if the_issue.issue.fields.assignee.emailAddress not in assignees:
                assignee = {"name": the_issue.issue.fields.assignee.name, "issues": {}}
                assignees[the_issue.issue.fields.assignee.emailAddress] = assignee
            else:
                assignee = assignees[the_issue.issue.fields.assignee.emailAddress]
            issues = assignee["issues"]
            issues[key] = the_issue.issue.fields.summary
        for email in assignees:
            subject = (
                "[NOTIFICATION] "
                + assignees[email]["name"]
                + " ("
                + email
                + ") unresolved Jira issue(s)"
            )
            body = "{assignee}({email}) was not updated the following Jira issue(s) over {days} day(s).\n".format(
                assignee=assignees[email]["name"], email=email, days=str(self.days)
            )
            for key in assignees[email]["issues"]:
                body += "  - {key} {summary}\n".format(
                    key=key, summary=assignees[email]["issues"][key]
                )
            # mail = i_mail(subject, body)
            # mail.send()
            print("!!! " + subject)

    def handle_jiramsg_command(self):
        if self.jira_key is None or len(self.jira_key) == 0:
            return
        if self.subcmd == "verify":
            jira, issue = get_jira_issue(
                self.jira_url, self.jira_username, self.jira_password, self.jira_key
            )
            b_update = self.option == "update"
            if get_issuetype(issue) == "Task":
                the_issue = analysis_task(jira, issue, self.debugobj)
                if (
                    "StanleySHuang@qnap.com".lower()
                    == issue.raw["fields"]["assignee"]["name"].lower()
                ):
                    if self.assignee is None:
                        self.assignee = "LukeLin@qnap.com"
                    comments = the_issue.issue.fields.comment.comments
                    if (
                        len(comments) == 0
                        or comments[len(comments) - 1].body.find(self.assignee) < 0
                    ):
                        issue.update(assignee={"name": self.assignee})
                        model, product, ver = extract_model(
                            the_issue.issue.fields.summary
                        )
                        if model == "qnap website":
                            message = "[~{assignee}],\n依照 [IEIxQNAPx電商 弱點報告 Jira 流程|https://ieinet-my.sharepoint.com/:p:/r/personal/stanleyshuang_qnap_com/_layouts/15/Doc.aspx?sourcedoc=%7BB65C71B5-7B6C-49B2-B55D-7A30550F3225%7D&file=IEIxQNAP%20Web%20%E5%BC%B1%E9%BB%9E%E5%A0%B1%E5%91%8A%20Jira%20%E6%B5%81%E7%A8%8B.pptx&action=edit&mobileredirect=true] 請協助驗證，謝謝。".format(
                                assignee=self.assignee
                            )
                        else:
                            message = "[~{assignee}],\n請協助驗證，謝謝。".format(
                                assignee=self.assignee
                            )
                        jira.add_comment(issue, message)
                        print("--- Add Comment: " + message)
        elif self.subcmd == "reassign":
            jira, issue = get_jira_issue(
                self.jira_url, self.jira_username, self.jira_password, self.jira_key
            )
            b_update = self.option == "update"
            from pkg._fdb.vulnrep_global_config import vglobalconfig

            global_config = vglobalconfig(self.data, self.downloads)
            if get_issuetype(issue) == "Task":
                the_issue = analysis_task(jira, issue, self.debugobj)
                model, product, ver = extract_model(the_issue.issue.fields.summary)
                weight = 1.0
                if model in [
                    "qnap cloud service",
                    "amiz cloud",
                    "qnap website",
                    "iei website",
                ]:
                    weight = 0.2
                elif the_issue.issue.fields.summary.lower().find("samba") >= 0:
                    weight = 1.0
                if self.assignee is None:
                    self.assignee = the_issue.rotate_assign_analyst(
                        product, self.data, self.downloads
                    )
                if self.assignee:
                    the_issue.issue.update(assignee={"name": self.assignee})
                    global_config.assign_analyst(self.assignee, weight=weight)
                    comments = the_issue.issue.fields.comment.comments
                    if (
                        len(comments) == 0
                        or comments[len(comments) - 1].body.find(self.assignee) < 0
                    ):
                        the_issue.jira.add_comment(
                            the_issue.issue,
                            "[~{assignee}],\n請協助分析，並給出您的意見。\n謝謝。".format(
                                assignee=self.assignee
                            ),
                        )
                    the_issue.debuglog_r(
                        "--- Update Assignee                      {assignee}".format(
                            assignee=self.assignee
                        )
                    )
            elif get_issuetype(issue) == "Bug":
                the_issue = vuln_bug(jira, issue, self.debugobj)
                the_task_issue = the_issue.find_task()
                if the_task_issue:
                    the_task_issue = analysis_task(jira, the_task_issue, self.debugobj)
                    model, product, ver = extract_model(the_issue.issue.fields.summary)
                    weight = 1.0
                    if model in [
                        "qnap cloud service",
                        "amiz cloud",
                        "qnap website",
                        "iei website",
                    ]:
                        weight = 0.2
                    elif the_issue.issue.fields.summary.lower().find("samba") >= 0:
                        weight = 1.0
                    if self.assignee is None:
                        self.assignee = the_task_issue.rotate_assign_analyst(
                            product, self.data, self.downloads
                        )
                    if self.assignee:
                        the_task_issue.issue.update(assignee={"name": self.assignee})
                        global_config.assign_analyst(self.assignee, weight=weight)
                        comments = the_issue.issue.fields.comment.comments
                        if (
                            len(comments) == 0
                            or comments[len(comments) - 1].body.find(self.assignee) < 0
                        ):
                            the_issue.jira.add_comment(
                                the_issue.issue,
                                "[~{assignee}],\n請協助分析，並給出您的意見。\n謝謝。".format(
                                    assignee=self.assignee
                                ),
                            )
                        the_task_issue.debuglog_r(
                            "--- Update Assignee                      {assignee}".format(
                                assignee=self.assignee
                            )
                        )
        elif self.subcmd == "invalid":
            jira, issue = get_jira_issue(
                self.jira_url, self.jira_username, self.jira_password, self.jira_key
            )
            if get_issuetype(issue) == "Task":
                the_issue = analysis_task(jira, issue, self.debugobj)
                dummy, fed_data, the_attachments = the_issue.get_investigation_info(
                    self.data, self.downloads
                )

                prompt = 'The reporter is "{vauthor}". '.format(vauthor=fed_data['vauthor'])
                prompt += 'The subject of the reporter is "{subject}". '.format(subject=the_issue.extract_sf_subject())
                prompt += "Write an email to inform the reporter that the report is rejected, politely. "
                prompt += "Include the subject in the email content to let the author know which report we mentioned. "
                prompt += "https://qnap-jira.qnap.com.tw/ and Jira key, i.e., 'INTSI000-xxx', are not visible to the researcher, so don't disclose these to the researcher.\n"
                prompt += 'The mail sender is "QNAP PSIRT".\n'
                gpt_return, gpt_translate = self.handle_gpt_command(the_issue, prompt, fed_data, the_attachments)

                prompt = 'The reporter is "{vauthor}". '.format(vauthor=fed_data['vauthor'])
                prompt += 'The subject of the reporter is "{subject}". '.format(subject=the_issue.extract_sf_subject())
                prompt += 'list the items to illustrate the reasons that the vulnerabilty report was rejected. '
                prompt += "In JSON format, 'author' is a string, 'subject' is a string, 'rejects' is an array containing the reasons of reject.\n"
                gpt_return_json, gpt_translate_json = self.handle_gpt_command(the_issue, prompt, fed_data, the_attachments, b_translate=False)

                b_update = self.option == "update"
                if b_update:
                    jira.add_comment(issue, "[GPT-INVALID]\n" + gpt_return)
                    jira.add_comment(issue, "[gpt-invalid]\n{noformat}\n" + gpt_return_json + "\n{noformat}\n")
                    if "abort" != issue.fields.status.name:
                        issue.update(assignee={"name": "StanleySHuang@qnap.com"})
                        jira.transition_issue(
                            issue, "51", # abort
                            customfield_13516={
                                "value": "others (please comment the reason)"
                            },
                            comment="此弱點報告不成立。",
                        )
                        print("--- Update Status                        Abort")
                    self.gsheet.update_fixed_field(
                        issue.key,
                        [
                            "n/a",
                            "n/a",
                            "n/a",
                            "n/a",
                            "n/a",
                            "n/a",
                            "n/a",
                            "n/a",
                            "n/a",
                            "n/a",
                            None,
                            "n/a",
                        ],
                    )
        elif self.subcmd == "finding_response":
            jira, issue = get_jira_issue(
                self.jira_url, self.jira_username, self.jira_password, self.jira_key
            )
            if get_issuetype(issue) == "Task":
                the_issue = analysis_task(jira, issue, self.debugobj)
                dummy, fed_data, the_attachments = the_issue.get_investigation_info(
                    self.data, self.downloads
                )

                prompt = 'The reporter is "{vauthor}". '.format(vauthor=fed_data['vauthor'])
                prompt += "Write a security finding response letter to inform the reporter that the report is accepted, politely.\n"
                prompt += "- The most important information is the sections with tags: [gpt_finding_response].\n"
                prompt += (
                    "- 不要用 summary 中的內容當作描述弱點報告的標題。因為這裡有 PSIRT 團隊所標記弱點內容的敏感資訊。\n"
                    "- [gpt_finding_response] 裡的 vuln_analysis_statement 中，每一個 subject 都要提到。\n"
                    "- [gpt_finding_response] 中，若有 reject_statement，每一個 subject 都要提到，並說明每個 reject 理由。\n"
                    "- [gpt_finding_response] 中，如果 collect_personal_data 內含說明文字時，必須引用。\n"
                    "- [gpt_finding_response] 中，如果 outscope 內含說明文字時，必須引用。\n"
                )
                prompt += "- severity level, CVSS score 等資訊只有在資安通報發布後才會揭露。\n"
                prompt += "- 在任何時候，都不要揭露 PSIRT 團隊成員姓名。\n"
                prompt += "- https://qnap-jira.qnap.com.tw/ and Jira key, i.e., 'INTSI000-xxx', are not visible to the researcher. Don't disclose these to the researcher.\n"
                prompt += "- 除非此弱點的 severity level 為 crtical，否則不用 critical 或 important 來形容弱點，這樣容易引起研究員的誤會。\n"
                prompt += "- 可適時告知獎金金額與漏洞修復進度。\n"
                prompt += "- 可適時告知 PSIRT 專家給予 report description 或 POC 品質的分數。\n"
                prompt += "- 如果 report description 分數低於 3，可以請研究員參考 https://www.qnap.com/en/security-bounty-program#osExampleModal https://www.qnap.com/en/security-bounty-program#cloudExampleModal 或 https://www.qnap.com/en/security-bounty-program#appExampleModal \n"
                prompt += '- The mail sender is "QNAP PSIRT"。\n\n'
                gpt_return, gpt_translate = self.handle_gpt_command(the_issue, prompt, fed_data, the_attachments)

                b_update = self.option == "update"
                if b_update:
                    jira.add_comment(issue, "[GPT-FINDING-RESPONSE]\n" + gpt_return)
                    ### Update label 'responsed'
                    if not the_issue.does_label_exist("responsed"):
                        the_issue.update_labels("responsed")
                    if the_issue.is_main_task():
                        the_issue.search_blocked()
                        for blocked_issue in the_issue.blocked_issues:
                            if get_issuetype(blocked_issue) == "Task":
                                blocked_task = analysis_task(the_issue.jira, blocked_issue, the_issue.debug_obj)
                                if not blocked_task.does_label_exist("responsed"):
                                    print("--- Label 子單: " + blocked_task.issue.key + " " + blocked_task.issue.fields.summary + " 已回應")
                                    blocked_task.update_labels("responsed")
                '''
                if gpt_return:
                    self.subcmd = "gpt_summary"
                    self.handle_jiramsg_command()
                '''

        elif self.subcmd == "more_info":
            jira, issue = get_jira_issue(
                self.jira_url, self.jira_username, self.jira_password, self.jira_key
            )
            if get_issuetype(issue) == "Task":
                the_issue = analysis_task(jira, issue, self.debugobj)
                dummy, fed_data, the_attachments = the_issue.get_investigation_info(
                    self.data, self.downloads
                )

                prompt = 'The reporter is "{vauthor}". '.format(vauthor=fed_data['vauthor'])
                prompt += "Write a security finding response letter to request more information from the researcher, politely.\n"
                prompt += "The most important information is the sections with tags: [gpt_more_info].\n"
                prompt += "https://qnap-jira.qnap.com.tw/ and Jira key, i.e., 'INTSI000-xxx', are not visible to the researcher. Don't disclose these to the researcher.\n"
                prompt += 'The mail sender is "QNAP PSIRT". It is not necessary to put personal name and the other information.\n'
                gpt_return, gpt_translate = self.handle_gpt_command(the_issue, prompt, fed_data, the_attachments)

                b_update = self.option == "update"
                if b_update:
                    jira.add_comment(issue, "[GPT-MORE_INFO]\n" + gpt_return)
        elif self.subcmd == "gpt_prompt":
            jira, issue = get_jira_issue(
                self.jira_url, self.jira_username, self.jira_password, self.jira_key
            )
            if get_issuetype(issue) == "Task":
                the_issue = analysis_task(jira, issue, self.debugobj)
                prompt, fed_data, the_attachments = the_issue.get_investigation_info(
                    self.data, self.downloads
                )
                if prompt is None:
                    return

                gpt_return, gpt_translate = self.handle_gpt_command(the_issue, prompt, fed_data, the_attachments)

                b_update = self.option == "update"
                if b_update:
                    jira.add_comment(issue, gpt_return)
        elif self.subcmd == "gpt_summary":
            b_update = self.option == "update"
            if not b_update:
                return
            jira, issue = get_jira_issue(
                self.jira_url, self.jira_username, self.jira_password, self.jira_key
            )
            if get_issuetype(issue) == "Task":
                the_issue = analysis_task(jira, issue, self.debugobj)

                str_customfield_13601 = the_issue.issue.raw["fields"]["customfield_13601"]
                if str_customfield_13601 is None or len(str_customfield_13601) == 0:
                    prompt, fed_data, the_attachments = the_issue.get_investigation_info(
                        self.data, self.downloads
                    )

                    prompt = "Summarize the following information in English:\n"
                    prompt += "* Describe the vulnerability\n"
                    prompt += "* Describe the possible risk and damages\n"
                    prompt += "* The needed premission to perform the attack\n"
                    prompt += "* The affected process, program or execuatble\n"
                    prompt += "* Shortly describe the PoC\n"
                    gpt_return, gpt_translate = self.handle_gpt_command(the_issue, prompt, fed_data, the_attachments)

                    # PgM Project Update: customfield_13601
                    the_issue.issue.update(fields={"customfield_13601": gpt_return + '\n' + gpt_translate})

    def handle_jiraadm_command(self):
        if self.jira_key is None or len(self.jira_key) == 0:
            return
        if self.subcmd == "rm_analysis":
            jira, issue = get_jira_issue(
                self.jira_url, self.jira_username, self.jira_password, self.jira_key
            )
            if get_issuetype(issue) == "Task":
                from pkg._qjira.batch_common import earse_analysis

                the_issue = analysis_task(jira, issue, self.debugobj)

                earse_analysis(
                    self.jira_key,
                    the_issue,
                    jira,
                    self.data,
                    self.downloads,
                    self.debugobj,
                    self.option,
                )
        elif self.subcmd == "get_finding_response":
            jira, issue = get_jira_issue(
                self.jira_url, self.jira_username, self.jira_password, self.jira_key
            )
            if get_issuetype(issue) == "Task":
                the_issue = analysis_task(jira, issue, self.debugobj)

                from pkg._util.util_file import get_sub_folder_list

                sub_folders = get_sub_folder_list(self.downloads + "/jira")

                if the_issue.is_main_task():
                    sf_data = {}
                    sf_case_num = the_issue.get_sf_case_num()
                    if sf_case_num:
                        case_num, created_date, email, name, sf_data = sf_get_data(
                            self.salesforce_orgid,
                            self.salesforce_username,
                            self.salesforce_password,
                            sf_case_num,
                        )
                        the_issue.set_sf_data(created_date, email, name, sf_data)
                    the_issue.trace_dependency()
                    all_issues = the_issue.dependent_issues
                    all_issues.append(the_issue)
                else:
                    all_issues = [the_issue]
                for task in all_issues:
                    if task.issue.key in sub_folders:
                        from pkg._fdb.vfinding_response import vfinding_response

                        vfinding_response = vfinding_response(self.data, self.downloads)
                        vfinding_response.read(task.issue.key)

    def handle_qsa_command(self):
        jira = JIRA(
            basic_auth=(self.jira_username, self.jira_password),
            options={"server": self.jira_url},
        )
        if self.jira_key and len(self.jira_key) > 0:
            jql = 'project=INTSI000 AND type=Task AND component=vulnerability_report AND summary ~ "CVE-*" AND (labels!=qsa OR labels is EMPTY) AND status != "abort" AND key = "{tickid}" ORDER BY created ASC'.format(
                tickid=self.jira_key
            )
        else:
            jql = 'project=INTSI000 AND type=Task AND component=vulnerability_report AND "Vulnerability Reporting Date">=-365d AND summary ~ "CVE-*" AND (labels!=qsa OR labels is EMPTY) AND status != "abort" ORDER BY created ASC'
        if self.option == "update":
            jira_tasks_routine(
                jira,
                jql,
                self.debugobj,
                self.salesforce_orgid,
                self.salesforce_username,
                self.salesforce_password,
                self.data,
                self.downloads,
                self.option,
                self.gsheet,
                None,
            )
        qsa_publish(
            jira,
            jql,
            self.gsheet,
            self.salesforce_orgid,
            self.salesforce_username,
            self.salesforce_password,
            self.data,
            self.downloads,
            debugobj=self.debugobj,
        )

    def handle_rn_command(self):
        from datetime import datetime
        from pkg._util.util_datetime import utc_to_local_str
        from pkg._util.util_file import get_sub_folder_list
        from pkg._fdb.raw import raw

        # Release Note 相關資料
        release_notes = {}
        update_date_str = utc_to_local_str(datetime.now(), format="%Y-%m-%d")
        if self.downloads:
            sub_folders = get_sub_folder_list(self.downloads + "/jira/")
            for sub_folder in sub_folders:
                filepath = (
                    self.downloads + "/jira/" + sub_folder + "/_raw.json"
                )  # '_raw.json'
                if os.path.isfile(filepath):
                    print(sub_folder)
                    issuekey = sub_folder
                    a_vraw = raw(self.data, self.downloads)
                    a_vraw.load(issuekey)
                    release_notes = a_vraw.retrieve_rn_in_releases(
                        issuekey, release_notes
                    )

            qsas = self.gsheet.get_records("qsa")
            published_qsa = set()
            for qsa in qsas:
                if qsa[10] and len(qsa[10]) > 0:
                    published_qsa.add(qsa[2])
                    print(qsa[2] + ":" + qsa[10])

            for index, (key, value) in enumerate(
                sorted(release_notes["releaseissue"].items(), reverse=True)
            ):
                #  print(f'Index: {index}, Key: {key}, Value: {value}')
                print("--- product: " + key)
                published = ""
                cveids = ""
                for cveid in sorted(value["cveid"]):
                    if cveid in published_qsa:
                        published += cveid + ","
                    cveids += cveid + ","
                print("--- published: " + published)
                print("--- cveid: " + cveids)
                jirakeys = ""
                for jirakey in sorted(value["jirakey"]):
                    jirakeys += jirakey + ","
                print("--- jirakey: " + jirakeys)
                rn_row = [
                    update_date_str,
                    key,
                    published,
                    cveids,
                    jirakeys,
                ]
                self.gsheet.update_release_note(rn_row)

    def handle_v5_command(self):
        from pkg._fdb.analysis import analysisException

        b_update = self.option == "update"

        jira = JIRA(
            basic_auth=(self.jira_username, self.jira_password),
            options={"server": self.jira_url},
        )
        jql = '(project=INTSI000 or project=CMNBSIMM) and type=Task and component=vulnerability_report and summary ~ "V5" order by key desc'
        todo_issues = i_issue.issue_filter(jira, jql)
        for issue in todo_issues:
            the_issue = analysis_task(
                jira, jira.issue(issue.key, expand="changelog"), self.debugobj
            )

            sf_data = {}
            sf_case_num = the_issue.get_sf_case_num()
            if sf_case_num:
                case_num, created_date, email, name, sf_data = sf_get_data(
                    self.salesforce_orgid,
                    self.salesforce_username,
                    self.salesforce_password,
                    sf_case_num,
                )
                the_issue.set_sf_data(created_date, email, name, sf_data)

            try:
                raw, bug_raws, release_raws = the_issue.check(
                    the_issue, the_issue, self.data, self.downloads, b_update=b_update
                )

                a_task_row = self.gsheet.read_atask_json(the_issue.issue.key)
                qsaid = ""
                QSAID_IDX = 1
                if (
                    "atask2" in a_task_row
                    and len(a_task_row["atask2"]) >= QSAID_IDX + 1
                ):
                    qsaid = a_task_row["atask2"][QSAID_IDX]

                cveid = ""
                CVEID_IDX = 6
                if (
                    "atask1" in a_task_row
                    and len(a_task_row["atask1"]) >= CVEID_IDX + 1
                ):
                    cveid = a_task_row["atask1"][CVEID_IDX]

                submitted = ""
                SUBMITTED_IDX = 3
                if (
                    "atask1" in a_task_row
                    and len(a_task_row["atask1"]) >= SUBMITTED_IDX + 1
                ):
                    submitted = a_task_row["atask1"][SUBMITTED_IDX]

                print("-------------------------------------------------------------")
                for release_raw in release_raws:
                    raw = [
                        release_raw["product"],
                        release_raw["version_n_build"],
                        qsaid,
                        cveid,
                        the_issue.issue.key,
                        submitted,
                        the_issue.issue.fields.summary,
                    ]
                    print(
                        "    "
                        + raw[0]
                        + ", "
                        + raw[1]
                        + ", "
                        + raw[2]
                        + ", "
                        + raw[3]
                        + ", "
                        + raw[4]
                        + ", "
                        + raw[5]
                        + ", "
                        + raw[6]
                    )
                    self.gsheet.update_v5(raw)
                print("-------------------------------------------------------------")
            except analysisException as error:
                if str(error) == "non-3rd-party-multi-CVE-IDs":
                    subject = "[{issuekey}] is not 3rd-party: split CVE IDs".format(
                        issuekey=the_issue.issue.key
                    )
                    body = "as title."
                    # mail = i_mail(subject, body)
                    # mail.send()
                    print("!!! " + subject)

    def handle_overdue_command(self):
        jira = JIRA(
            basic_auth=(self.jira_username, self.jira_password),
            options={"server": self.jira_url},
        )
        if self.jira_key and len(self.jira_key) > 0:
            jql = 'project = INTSI000 AND type = Bug AND resolution = Unresolved AND (summary ~ V5 OR summary ~ V4) AND "Vulnerability Reporting Date">=-365d AND "Vulnerability Reporting Date" <= -90d AND key = "{tickid}" ORDER BY priority DESC, updated DESC'.format(
                tickid=self.jira_key
            )
        else:
            jql = 'project = INTSI000 AND type = Bug AND resolution = Unresolved AND (summary ~ V5 OR summary ~ V4) AND "Vulnerability Reporting Date">=-365d AND "Vulnerability Reporting Date" <= -90d                      ORDER BY priority DESC, updated DESC'
        todo_jira_keys = jira_filter(jira, jql)

        from datetime import datetime
        from pkg._util.util_datetime import utc_to_local_str, duration_days

        update_date_str = utc_to_local_str(datetime.now(), format="%Y-%m-%d")
        for issuekey in todo_jira_keys:
            the_issue = vuln_bug(
                jira, jira.issue(issuekey, expand="changelog"), self.debugobj
            )

            s_format = "%Y-%m-%d"
            local_tz_str = "Asia/Taipei"
            the_date, the_date_str = the_issue.get_time_n_str(
                the_issue.issue.raw["fields"]["customfield_16400"],
                s_format=s_format,
                local_tz_str=local_tz_str,
            )
            now = datetime.now()
            overdue = duration_days(the_date, now)

            ### overdue by bug created date
            the_created_date, the_created_date_str = the_issue.get_created_n_str()
            o2 = duration_days(the_created_date, now)

            print(
                "--------------------------------------------------------------------"
            )
            print("--- jirakey: " + the_issue.issue.key)
            print(
                "--- reported date: "
                + the_issue.issue.raw["fields"]["customfield_16400"]
            )
            print("--- overdue: " + str(overdue))
            print("--- bug created date: " + the_issue.issue.fields.created)
            print("--- overdue 2: " + str(o2))
            print("--- summary: " + the_issue.issue.fields.summary)
            print("--- owner: " + the_issue.issue.fields.assignee.emailAddress)
            print(
                "--- url: https://qnap-jira.qnap.com.tw/browse/" + the_issue.issue.key
            )
            overdue_row = [
                update_date_str,
                the_issue.issue.key,
                the_issue.issue.raw["fields"]["customfield_16400"],
                str(overdue),
                the_issue.issue.fields.created[:10],
                str(o2),
                the_issue.issue.fields.summary,
                the_issue.issue.fields.assignee.emailAddress,
                "https://qnap-jira.qnap.com.tw/browse/" + the_issue.issue.key,
            ]
            self.gsheet.update_overdue(overdue_row)

    def handle_triage_command(self):
        jira = JIRA(
            basic_auth=(self.jira_username, self.jira_password),
            options={"server": self.jira_url},
        )
        if self.jira_key and len(self.jira_key) > 0:
            jql = 'project=INTSI000 AND type=Task AND component=vulnerability_report AND summary !~ "Mantis#" AND (description ~ "qnap.lightning.force.com/lightning/" OR reporter = "myronsu@qnap.com") AND status != "abort" AND key = "{tickid}" ORDER BY created DESC, updated DESC'.format(
                tickid=self.jira_key
            )
        else:
            jql = 'project=INTSI000 AND type=Task AND component=vulnerability_report AND "Vulnerability Reporting Date">=-365d AND summary !~ "Mantis#" AND (description ~ "qnap.lightning.force.com/lightning/" OR reporter = "myronsu@qnap.com") AND  (labels!=paid OR labels is EMPTY) AND status != "abort" ORDER BY created DESC, updated DESC'
        triage(
            jira,
            jql,
            self.gsheet,
            self.salesforce_orgid,
            self.salesforce_username,
            self.salesforce_password,
            self.data,
            self.downloads,
            debugobj=self.debugobj,
            option=self.option,
        )

    def handle_bounty_nomination_command(self):
        jira = JIRA(
            basic_auth=(self.jira_username, self.jira_password),
            options={"server": self.jira_url},
        )
        if self.jira_key and len(self.jira_key) > 0:
            jql = 'project=INTSI000 AND type=Task AND component=vulnerability_report AND summary !~ "Mantis#" AND (description ~ "qnap.lightning.force.com/lightning/" OR reporter = "myronsu@qnap.com") AND  (labels!=paid OR labels is EMPTY) AND status != "abort" AND key = "{tickid}" ORDER BY created DESC, updated DESC'.format(
                tickid=self.jira_key
            )
        else:
            jql = 'project=INTSI000 AND type=Task AND component=vulnerability_report AND "Vulnerability Reporting Date">=-365d AND summary !~ "Mantis#" AND (description ~ "qnap.lightning.force.com/lightning/" OR reporter = "myronsu@qnap.com") AND  (labels!=paid OR labels is EMPTY) AND status != "abort" ORDER BY created DESC, updated DESC'
        if self.option == "update":
            jira_tasks_routine(
                jira,
                jql,
                self.debugobj,
                self.salesforce_orgid,
                self.salesforce_username,
                self.salesforce_password,
                self.data,
                self.downloads,
                self.option,
                self.gsheet,
                None,
            )
        bounty_nomination(
            jira,
            jql,
            self.gsheet,
            self.salesforce_orgid,
            self.salesforce_username,
            self.salesforce_password,
            self.data,
            self.downloads,
            debugobj=self.debugobj,
        )

    def handle_researcher_command(self):
        jira = JIRA(
            basic_auth=(self.jira_username, self.jira_password),
            options={"server": self.jira_url},
        )
        jql = 'project=INTSI000 and type=Task and component=vulnerability_report and TEXT ~ "{researcher_email}" and "Vulnerability Reporting Date">=-730d order by key desc'.format(
            researcher_email=self.researcher_email
        )
        researcher_reward(
            jira,
            jql,
            self.gsheet,
            self.salesforce_orgid,
            self.salesforce_username,
            self.salesforce_password,
            self.data,
            self.downloads,
            debugobj=self.debugobj,
            researcher_email=self.researcher_email,
        )

    def handle_subtask_command(self):
        if self.jira_key is None or len(self.jira_key) == 0:
            return
        jira, issue = get_jira_issue(
            self.jira_url, self.jira_username, self.jira_password, self.jira_key
        )
        if get_issuetype(issue) == "Task":
            the_issue = analysis_task(jira, issue, self.debugobj)
            b_update = self.option == "update"
            if self.group_name:
                jira_subtask(jira, issue, b_update, group_name=self.group_name)
            else:
                jira_subtask(jira, issue, b_update)

    def handle_mantis_command(self):
        if self.mantis_id is None or self.mantis_id < 0:
            return
        mantis_id_tag = "Mantis#{mantis_id}".format(mantis_id=str(self.mantis_id))
        m_ticket = get_mantis_ticket(
            self.mantis_url,
            self.mantis_username,
            self.mantis_password,
            self.mantis_project,
            self.mantis_id,
            self.downloads,
        )
        (
            summary,
            description,
            additional_information,
            txt_filename,
            lines,
        ) = m_ticket.extract_content_for_submission()

        ### Search if there is the issue created
        jira = JIRA(
            basic_auth=(self.jira_username, self.jira_password),
            options={"server": self.jira_url},
        )
        jql = 'project=INTSI000 and type=Task and summary ~ "{mantis_id_tag}" order by key desc'.format(
            mantis_id_tag=mantis_id_tag
        )
        todo_issue_keys = jira_filter(jira, jql)
        if todo_issue_keys is None or len(todo_issue_keys) == 0:
            j_summary = "[" + mantis_id_tag + "] " + summary
            j_description = (
                "["
                + mantis_id_tag
                + "|https://bugtracking.qnap.com.tw/mantis/view.php?id="
                + str(self.mantis_id)
                + "]\n{noformat}\n"
                + description
                + "\n{noformat}\n"
            )
            if additional_information and len(additional_information) > 0:
                j_description += "\n[" + "Additional Information" + "]\n"
                j_description += (
                    "{noformat}\n" + additional_information + "\n{noformat}\n"
                )
            if txt_filename and len(txt_filename):
                j_description += "\n[" + txt_filename + "]\n"
                j_description += "{noformat}\n"
                for line in lines:
                    j_description += line + "\n"
                j_description += "{noformat}\n"
            issue_dict = {
                "project": {"key": "INTSI000"},
                "summary": j_summary,
                "description": j_description,
                "issuetype": {"name": "Task"},
                "assignee": {"name": "StanleySHuang@qnap.com"},
            }
            print("    summary = " + j_summary)
            print("    description = " + j_description)
            new_issue = jira.create_issue(fields=issue_dict)
            # new_issue.raw['fields']["customfield_14000"]
            print(
                "*** New issue {key} {summary} created".format(
                    key=new_issue.key, summary=new_issue.fields.summary
                )
            )
            if self.the_watcher:
                b_update = self.option == "update"
                jira_add_watchers(jira, new_issue, [self.the_watcher], b_update)
            if "reporter" in m_ticket.issue:
                b_update = self.option == "update"
                reporter = m_ticket.issue["reporter"]
                the_watcher = reporter["email"]
                jira_add_watchers(jira, new_issue, [the_watcher], b_update)
            m_ticket.add_note("https://qnap-jira.qnap.com.tw/browse/" + new_issue.key)

    def handle_mail_command(self):
        if self.mail_data is None or len(self.mail_data) == 0:
            return
        mail_data_list = self.mail_data.split(",")
        if len(mail_data_list) >= 4:
            subject = mail_data_list[0]
            body = mail_data_list[1]
            mail_from = mail_data_list[2]
            mail_tos = mail_data_list[3].split(";")
            mail = i_mail(subject, body, mail_from, mail_tos)
            mail.send()

    def handle_gpt_command(self, the_issue, prompt, fed_data, the_attachments, b_translate=True):
        print("> GPT 查詢：\n")
        print(prompt)
        gpt_return = None
        while gpt_return is None:
            self.prompt = "以下為弱點報告與其分析資料:\n"
            self.prompt += the_issue.make_fed_data(fed_data, the_attachments) + '\n\n'
            self.prompt += "----\n"
            self.prompt += prompt
            gpt_return = gpt_chat_completion(self.prompt)
            if gpt_return is None:
                if len(the_attachments) > 0:
                    the_attachments.pop()
                    print('!!! 資料過多：捨棄附件')
                else:
                    if len(fed_data['comments'])>0:
                        fed_data['comments'].pop()
                        print('!!! 資料過多：捨棄註解')

        if b_translate:
            gpt_translate = gpt_chat_completion("翻譯為繁體中文\n" + gpt_return)
        else:
            gpt_translate = None
        return gpt_return, gpt_translate

    def handle_unittest_command(self):
        import unittest

        tests = unittest.TestLoader().discover("tests")
        unittest.TextTestRunner(verbosity=2).run(tests)


def main():
    if len(sys.argv) == 1:
        usage()
    handler = CommandHandler(sys.argv)
    handler.execute_command()
    print("--------")
    quit()


### the main program
if __name__ == "__main__":
    main()


for idx in range(1, len(sys.argv)):
    if sys.argv[idx].find("subtask:") >= 0:
        cmd = "subtask"
        input_data = sys.argv[idx][len("subtask:") :]
        if input_data.find(":") >= 0:
            inputs = input_data.split(":")
            jira_id = inputs[0]
            group_name = inputs[1]
        else:
            jira_id = input_data
            group_name = None
    elif sys.argv[idx].find("create_bugs:") >= 0:
        cmd = "create_bugs"
        cmd_tokens = sys.argv[idx].split(":")
        jira_id = cmd_tokens[1]
        print("jira_id: " + jira_id)
        assignee = None
        if len(cmd_tokens) > 2:
            assignee = cmd_tokens[2]
            print("assignee: " + assignee)
    elif sys.argv[idx].find("jira:notes:") >= 0:
        cmd = "jira:notes"
        jirakeys = sys.argv[idx][len("jira:notes:") :]
    elif sys.argv[idx].find("adm:rmfile:") >= 0:
        cmd = "adm:rmfile"
        filename = sys.argv[idx][len("adm:rmfile:") :]
    elif sys.argv[idx].find("adm:replacekey:") >= 0:
        cmd = "adm:replacekey"
        cmd_tokens = sys.argv[idx].split(":")
        jirakey = cmd_tokens[2]
        print("jirakey: " + jirakey)
        filename = cmd_tokens[3]
        print("filename: " + filename)
        fromkey = cmd_tokens[4]
        print("fromkey: " + fromkey)
        tokey = cmd_tokens[5]
        print("tokey: " + tokey)
    else:
        jira_id = sys.argv[idx]

if cmd == "subtask" and jira_id and len(jira_id) > 0:
    jira, issue = get_jira_issue(jira_url, jira_username, jira_password, jira_id)
    b_update = option == "update"
    if group_name:
        jira_subtask(issue, b_update, group_name=group_name)
    else:
        jira_subtask(issue, b_update)
elif cmd == "create_bugs" and jira_id and len(jira_id) > 0:
    jira, issue = get_jira_issue(jira_url, jira_username, jira_password, jira_id)
    b_update = option == "update"
    if get_issuetype(issue) == "Task":
        the_issue = analysis_task(jira, issue, debugobj)
        if (
            "StanleySHuang@qnap.com".lower()
            == issue.raw["fields"]["assignee"]["name"].lower()
        ):
            if assignee is None:
                assignee = "LukeLin@qnap.com"
            comments = the_issue.issue.fields.comment.comments
            if (
                len(comments) == 0
                or comments[len(comments) - 1].body.find(assignee) < 0
            ):
                issue.update(assignee={"name": assignee})
                message = "[~{assignee}],\n請協助開 Bug 單並驗證，謝謝。".format(
                    assignee=assignee
                )
                jira.add_comment(issue, message)
                print("--- Add Comment: " + message)
elif cmd == "jira.notes" and jirakeys and len(jirakeys) > 0:
    jira = JIRA(basic_auth=(jira_username, jira_password), options={"server": jira_url})
    jirakey_list = jirakeys.split("|")
    for jirakey in jirakey_list:
        issue = jira.issue(jirakey.strip(), expand="changelog")
        if get_issuetype(issue) == "Task":
            the_issue = analysis_task(jira, issue, debugobj)
            notes_done_close_task(jira, the_issue, gsheet)
elif cmd == "adm:rmfile":
    from pkg._util.util_file import get_sub_folder_list

    if downloads:
        sub_folders = get_sub_folder_list(downloads)
        for sub_folder in sub_folders:
            filepath = (
                downloads + "/" + sub_folder + "/" + filename
            )  # 'xreleaseproc.json'
            if os.path.isfile(filepath):
                print(filepath)
                os.remove(filepath)
elif cmd == "adm:replacekey":
    from pkg._util.util_file import get_sub_folder_list

    if downloads:
        if jirakey == "-":
            sub_folders = get_sub_folder_list(downloads)
            for sub_folder in sub_folders:
                filepath = downloads + "/" + sub_folder + "/" + filename
                if os.path.isfile(filepath):
                    print(filepath)
        else:
            filepath = downloads + "/" + jirakey + "/" + filename
            if os.path.isfile(filepath):
                print(filepath)
else:
    pass
