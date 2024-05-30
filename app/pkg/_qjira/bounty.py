#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2023-01-04
#
###############################################################################

from datetime import datetime

from pkg._qjira.batch_common import jira_filter, cat_issues_by_researcher
from pkg._qjira.description import extract_severity_level, extract_jirakey_num
from pkg._util.util_datetime import utc_to_local_str, duration_days


def which_phase(reward, status, b_paid_label, b_escalate_label):
    if (
        "severity_level" in reward
        and "one_fixed" in reward
        and ("reward_draft" not in reward and not b_paid_label)
    ):
        return "completed"
    elif (
        "severity_level" in reward
        and ("since_submited" in reward and reward["since_submited"] > 90)
        and ("reward_draft" not in reward and not b_paid_label)
    ):
        return "overdue"
    elif "severity_level" in reward and (
        "reward_draft" not in reward and not b_paid_label
    ):
        return "resolving"
    elif b_escalate_label and status not in ["abort"] and not b_paid_label:
        return "escalate"
    elif (
        "severity_level" not in reward
        and ("reward_draft" not in reward and not b_paid_label)
        and status not in ["abort"]
    ):
        return "analyzing"
    elif (
        "severity_level" in reward
        and "one_fixed" not in reward
        and ("reward_draft" in reward or b_paid_label)
    ):
        return "resolving_but_paid"
    elif (
        ("severity_level" in reward and "one_fixed" in reward) or b_escalate_label
    ) and ("reward_draft" in reward or b_paid_label):
        return "paid"
    elif "severity_level" not in reward and status in ["abort"]:
        return "invalid"
    else:
        return "misc"


def make_gsheet(the_researcher_issues, gsheet):
    """
    條件為： 至少一個平台已解 one_fixed == 'Yes' 或 開單超過 90 天 since_submited > 90
    """
    for researcher_email in the_researcher_issues:
        profile = the_researcher_issues[researcher_email]["profile"]
        if "name" not in profile or len(profile["name"]) == 0:
            name = ""
        else:
            name = profile["name"]
        email = profile["email"]
        if "paypal" not in profile or len(profile["paypal"]) == 0:
            paypal = ""
        else:
            paypal = profile["paypal"]
        for issue in the_researcher_issues[researcher_email]["issues"]:
            reward = the_researcher_issues[researcher_email]["rewards"][issue.issue.key]
            severity_level = extract_severity_level(issue.issue.fields.summary)
            if (
                (
                    ("one_fixed" in reward and reward["one_fixed"])
                    or ("since_submited" in reward and reward["since_submited"] > 90)
                )
                and severity_level
            ) or (issue.does_label_exist("bounty_escalate")):
                nomination_date_str = utc_to_local_str(
                    datetime.now(), format="%Y-%m-%d"
                )
                jirakey_num = extract_jirakey_num(issue.issue.key)
                reward = str(
                    calc_reward(
                        profile,
                        issue.issue.fields.summary,
                        severity_level,
                        issue.analysis,
                        b_location=jirakey_num < 3855,
                    )
                )
                sf_case_num = issue.sf_data["sf_case_num"]
                submitted_date = issue.sf_data["created_date"]
                summary = issue.issue.fields.summary
                jira_key = issue.issue.key
                sf_url = (
                    "https://qnap.lightning.force.com/lightning/r/Case/"
                    + issue.sf_data["sf_case_id"]
                    + "/view"
                )
                jira_url = "https://qnap-jira.qnap.com.tw/browse/" + jira_key
                bounty_nomination = [
                    nomination_date_str,
                    name,
                    email,
                    paypal,
                    reward,
                    sf_case_num,
                    jira_key,
                    submitted_date,
                    summary,
                    sf_url,
                    jira_url,
                ]
                gsheet.update_bounty_nomination(bounty_nomination)


g_gni = {
    "Sudan": 1410,
    "Kenya": 1580,  # 4950 in 2021
    "?": 1580,
    "Pakistan": 1580,
    "Bangladesh": 1750,
    "India": 2020,  # 7220 in 2021
    "Viet Nam": 2890,
    "Morocco": 3240,
    "Sylia": 3800,
    "Indonesia": 3840,
    "Philippines": 3860,
    "Jordan": 4210,  # 2020
    "Iraq": 4740,  # 2020
    "China": 9771,  # 19170 in 2021
    "Russia": 9920,
    "Malaysia": 10120,  # 28730 in 2021
    "Brazil": 11175,
    "Poland": 14510,
    "World": 18627,  # in 2021
    "Taiwan": 25360,
    "Spain": 29450,
    "South Korea": 30600,
    "Italy": 33560,
    "Canada": 37147,
    "Israel": 40850,
    "UAE": 41010,
    "France": 41070,
    "United Kingdom": 41330,
    "Germany": 47450,
    "Iceland": 49866,
    "Austria": 55960,
    "Singapore": 58770,
    "US": 62850,
    "Switzerland": 83580,
}

g_reward = {
    "[v5]": 15000,
    "[v4]": 750,
    "[v3]": 300,
    "[v2]": 100,
    "[v1]": 30,
}


def calc_reward(profile, summary, severity_level, analysis, b_location=False):
    from pkg._qjira.description import extract_model

    model, product, ver = extract_model(summary)
    if model and len(model) > 0:
        vulnable_module = model.lower()
    else:
        print("!!! Extract Model error: " + summary)
        exit()
    if severity_level is None:
        print("!!! severity_level is None, Summary: " + summary)
        return 0
    else:
        money = g_reward[severity_level.lower()]

    ratio = 1.0
    if vulnable_module in [
        "iei website",
        "qnap website",
        "web",
        "windows",
        "macos",
        "utility",
        "windows utility",
        "macos utility",
    ]:
        money *= 0.7
        if "country" not in profile:
            country = "?"
        else:
            country = profile["country"]
        ratio = (g_gni[country] ** 0.5) / (g_gni["Taiwan"] ** 0.5)
    elif vulnable_module in [
        "qpkg",
        "cloud web",
        "koimeeter ios",
        "qmiix android",
        "qnap cloud service",
        "android",
        "ios",
        "mobile",
        "amiz cloud",
        "quwan",
        "qmiro",
    ]:
        money *= 0.83
        if b_location:
            if "country" not in profile:
                country = "?"
            else:
                country = profile["country"]
            ratio = (g_gni[country] ** 0.5) / (g_gni["Taiwan"] ** 0.5)
    elif vulnable_module in ["qts", "quts hero", "qutscloud"]:
        money *= 1.0
    elif vulnable_module in ["main"]:
        money = 0.0
    else:
        print("??? vulnable_module = " + vulnable_module)
        money = 0.0

    # print('ratio = ' + str(round(ratio*100)) + '%')
    money *= ratio
    if analysis:  # for example product == 'main'
        if (
            "description" in analysis.json_obj
            and analysis.json_obj["description"]
            and analysis.json_obj["description"] >= 4
        ):
            money *= analysis.json_obj["description"] * 0.05 + 0.85
        if "poc" in analysis.json_obj and analysis.json_obj["poc"] >= 4:
            money *= analysis.json_obj["poc"] * 0.05 + 0.85
        if (
            "suggestion" in analysis.json_obj
            and analysis.json_obj["suggestion"]
            and analysis.json_obj["suggestion"] >= 4
        ):
            money *= analysis.json_obj["suggestion"] * 0.05 + 0.85
    the_money = round(money, -1)
    return the_money


def reward(
    jira,
    jql,
    gsheet,
    salesforce_orgid,
    salesforce_username,
    salesforce_password,
    apphome_data,
    apphome_downloads,
    debugobj=None,
    researcher_email=None,
):
    all_reward_notifications = {}
    ### 收集特定 Jira Task
    todo_task_keys = jira_filter(jira, jql)

    ### 依照 researcher email 分類 Jira Tasks
    the_researcher_issues = cat_issues_by_researcher(
        jira,
        todo_task_keys,
        salesforce_orgid,
        salesforce_username,
        salesforce_password,
        debugobj,
        researcher_email,
    )
    """
    {   email:  {
            'profile': profile,
            'issues': issues,      # list
            'rewards': rewards     # key: reward
        }
    }
    """

    ### 分析每個 researcher 的 Jira Task 情況
    from pkg._fdb.vbountyhunter import vbountyhunter

    vbountyhunter = vbountyhunter(apphome_data, apphome_downloads)
    for researcher_email in the_researcher_issues:
        profile = vbountyhunter.retrieve_profile(researcher_email)
        """
        profile = {
            'email': '',
            'country': '',
            'name': '',
            'paypal': '',
            'bank': '',
        }
        """

        if profile:
            the_researcher_issues[researcher_email]["profile"] = profile
        a_researcher_issues = the_researcher_issues[researcher_email]["issues"]

        reward_draft_dates, rewards = gsheet.batch_get_reward_draft_n_reward(
            a_researcher_issues
        )

        if "rewards" not in the_researcher_issues[researcher_email]:
            the_researcher_issues[researcher_email]["rewards"] = {}

        reward_notification = (
            output_analyzing
        ) = (
            output_invalid
        ) = (
            output_resolving
        ) = (
            output_overdue
        ) = (
            output_escalate
        ) = (
            output_completed
        ) = output_sf_nums = output_paid = output_resolving_but_paid = output_misc = ""
        output_i_total_reward = 0
        for i in range(len(a_researcher_issues)):
            """
            a_researcher_issues[i].sf_data = {
                    "researcher_email": '', 
                    "researcher_name": '',
                    "created_date": '',
                    "sf_case_num": '',

                }
            """
            reward = a_researcher_issues[i].reward_view(
                a_researcher_issues[i],
                None,
                apphome_data,
                apphome_downloads,
                b_update=False,
            )
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
                'suggestion_score': 報告品質
                'since_submited': 開單至今
            }
            """
            key = a_researcher_issues[i].issue.key
            the_money = -1
            if (
                key in reward_draft_dates
                and reward_draft_dates[key]
                and len(reward_draft_dates[key]) > 0
                and reward_draft_dates[key] != "n/a"
            ):
                reward["reward_draft"] = reward_draft_dates[key]
            import re

            if (
                key in rewards
                and rewards[key]
                and len(rewards[key]) > 0
                and rewards[key] != "n/a"
            ):
                m = re.search(r"\$?(\d{1,5}).?", rewards[key])
                if m and m.group(1):
                    the_money = int(m.group(1))
                else:
                    print("money parsed ERROR!!!")
                    exit()
            the_researcher_issues[researcher_email]["rewards"][
                a_researcher_issues[i].issue.key
            ] = reward  # reward 資料收集完成
            ###
            s_format = "%Y-%m-%dT%H:%M:%S.000+0800"
            local_tz_str = "Asia/Taipei"
            created_date, created_date_str = a_researcher_issues[i].get_time_n_str(
                a_researcher_issues[i].issue.fields.created,
                s_format=s_format,
                local_tz_str=local_tz_str,
            )
            now = datetime.now()
            reward["since_submited"] = duration_days(created_date, now)

            phase = which_phase(
                reward,
                a_researcher_issues[i].get_status_name(),
                a_researcher_issues[i].does_label_exist("paid"),
                a_researcher_issues[i].does_label_exist("bounty_escalate"),
            )
            if phase == "completed":
                if profile:
                    severity_level = extract_severity_level(reward["summary"])
                    if severity_level:
                        summary = a_researcher_issues[i].issue.fields.summary
                        analysis = a_researcher_issues[i].analysis
                        jirakey_num = extract_jirakey_num(
                            a_researcher_issues[i].issue.key
                        )
                        if the_money < 0:
                            the_money = calc_reward(
                                profile,
                                summary,
                                severity_level,
                                analysis,
                                b_location=jirakey_num < 3855,
                            )
                        output_i_total_reward += the_money
                        str_money = "$" + str(the_money)
                        output_completed += (
                            "  " + reward["summary"] + " - " + str_money + "\n"
                        )
                        if len(output_sf_nums) > 0:
                            output_sf_nums += "|"
                        output_sf_nums += reward["sf_num"]
                        # gsheet.set_proposed_reward(a_researcher_issues[i], str_money)
                    else:
                        output_completed += "  " + reward["summary"] + "\n"
                        if len(output_sf_nums) > 0:
                            output_sf_nums += "|"
                        output_sf_nums += reward["sf_num"]
                else:
                    output_completed += "  " + reward["summary"] + "\n"
                    if len(output_sf_nums) > 0:
                        output_sf_nums += "|"
                    output_sf_nums += reward["sf_num"]
            if phase == "overdue":
                if profile:
                    severity_level = extract_severity_level(reward["summary"])
                    if severity_level:
                        summary = a_researcher_issues[i].issue.fields.summary
                        analysis = a_researcher_issues[i].analysis
                        jirakey_num = extract_jirakey_num(
                            a_researcher_issues[i].issue.key
                        )
                        if the_money < 0:
                            the_money = calc_reward(
                                profile,
                                summary,
                                severity_level,
                                analysis,
                                b_location=jirakey_num < 3855,
                            )
                        output_i_total_reward += the_money
                        str_money = "$" + str(the_money)
                        output_overdue += (
                            "  " + reward["summary"] + " - " + str_money + "\n"
                        )
                        if len(output_sf_nums) > 0:
                            output_sf_nums += "|"
                        output_sf_nums += reward["sf_num"]
                        # gsheet.set_proposed_reward(a_researcher_issues[i], str_money)
                    else:
                        output_overdue += "  " + reward["summary"] + "\n"
                        if len(output_sf_nums) > 0:
                            output_sf_nums += "|"
                        output_sf_nums += reward["sf_num"]
                else:
                    output_overdue += "  " + reward["summary"] + "\n"
                    if len(output_sf_nums) > 0:
                        output_sf_nums += "|"
                    output_sf_nums += reward["sf_num"]
            elif phase == "resolving":
                if profile:
                    severity_level = extract_severity_level(reward["summary"])
                    if severity_level:
                        summary = a_researcher_issues[i].issue.fields.summary
                        analysis = a_researcher_issues[i].analysis
                        jirakey_num = extract_jirakey_num(
                            a_researcher_issues[i].issue.key
                        )
                        if the_money < 0:
                            the_money = calc_reward(
                                profile,
                                summary,
                                severity_level,
                                analysis,
                                b_location=jirakey_num < 3855,
                            )
                        str_money = "$" + str(the_money)
                        output_resolving += (
                            "  " + reward["summary"] + " - " + str_money + "\n"
                        )
                    else:
                        output_resolving += "  " + reward["summary"] + "\n"
                else:
                    output_resolving += "  " + reward["summary"] + "\n"
            elif phase == "escalate":
                if the_money > 0:
                    output_i_total_reward += the_money
                    str_money = "$" + str(the_money)
                    output_escalate += (
                        "  " + reward["summary"] + " - " + str_money + "\n"
                    )
                else:
                    output_escalate += "  " + reward["summary"] + "\n"
            elif phase == "analyzing":
                output_analyzing += "  " + reward["summary"] + "\n"
            elif phase == "resolving_but_paid":
                output_resolving_but_paid += "  " + reward["summary"] + "\n"
            elif phase == "paid":
                output_paid += "  " + reward["summary"] + "\n"
            elif phase == "invalid":
                output_invalid += "  " + reward["summary"] + "\n"
            else:
                output_misc += "  " + reward["summary"] + "\n"

        if profile:
            if "country" in profile:
                country = profile["country"]
            else:
                country = ""
            if "name" in profile:
                name = profile["name"]
            else:
                name = ""
            reward_notification = "{country} 研究員： {name}\n".format(
                country=country, name=name
            )

        reward_notification += "completed:\n"
        reward_notification += output_completed + "\n"
        reward_notification += "overdue\n"
        reward_notification += output_overdue + "\n"
        reward_notification += "escalate\n"
        reward_notification += output_escalate + "\n"
        reward_notification += "resolving:\n"
        reward_notification += output_resolving + "\n"
        reward_notification += "analyzing:\n"
        reward_notification += output_analyzing + "\n"
        reward_notification += "resolving_but_paid:\n"
        reward_notification += output_resolving_but_paid + "\n"
        reward_notification += "paid:\n"
        reward_notification += output_paid + "\n"
        reward_notification += "invalid:\n"
        reward_notification += output_invalid + "\n"
        reward_notification += "misc:\n"
        reward_notification += output_misc + "\n"
        if profile:
            if "country" in profile:
                country = profile["country"]
            else:
                country = ""
            if "name" in profile:
                name = profile["name"]
            else:
                name = ""
            reward_notification += (
                "\n「NOTES 簽呈」 ----------------------------------------------\n"
            )
            reward_notification += (
                "發放資安研究員「安全漏洞獎勵計畫」獎勵：{name} - {sf_nums}\n\n".format(
                    name=name, sf_nums=output_sf_nums
                )
            )
            reward_notification += "{country} 研究員： {name} ({email})\n".format(
                country=country, name=name, email=profile["email"]
            )
            reward_notification += output_completed + "\n"
            reward_notification += output_overdue + "\n"
            reward_notification += output_escalate + "\n"
            reward_notification += "獎金 ${total_reward}\n獎金會議紀錄：\n".format(
                total_reward=str(output_i_total_reward)
            )
            # reward_notification += '[security_bounty_program-reward.xlsx](https://ieinet-my.sharepoint.com/:x:/r/personal/stanleyshuang_qnap_com/_layouts/15/Doc.aspx?sourcedoc=%7BC382A990-EF58-4B10-B00C-F0C36A8DB69B%7D&file=security_bounty_program-reward.xlsx&action=default&mobileredirect=true&cid=76f56345-f9d8-47f0-aeb4-f1a54b47c752)\n'
            reward_notification += "https://ieinet-my.sharepoint.com/:x:/r/personal/stanleyshuang_qnap_com/Documents/2023/%5BTLP-RED%5D%20classified/security_bounty_program-reward.xlsx?d=wc382a990ef584b10b00cf0c36a8db69b&csf=1&web=1&e=7n3UyI\n"
            if "paypal" in profile:
                if (
                    profile["paypal"].lower().find("swift:") >= 0
                    and profile["paypal"].lower().find("acc:") >= 0
                ):
                    if "bank" in profile:
                        if output_i_total_reward >= 400:
                            method = " (SHA) "
                        else:
                            method = " (OUR 全額到匯) "
                        reward_notification += "\n" + profile["bank"] + "\n\n"
                        reward_notification += "依獎勵規則，擬發放 ${total_reward} 獎金，由銀行電匯{method}支付，{paypal}。並請財務協助辦理。\n".format(
                            total_reward=str(output_i_total_reward),
                            method=method,
                            paypal=profile["paypal"],
                        )
                    else:
                        reward_notification += "資安研究員銀行帳號資訊尚未收集 -----------------------------\n\n"
                else:
                    reward_notification += "依獎勵規則，擬發放 ${total_reward} 獎金，由 Paypal 帳號支付 {paypal} 於此項研究回報案，並請財務協助辦理。\n".format(
                        total_reward=str(output_i_total_reward),
                        paypal=profile["paypal"],
                    )
                reward_notification += (
                    "------------------------------------------------------------\n\n"
                )
            else:
                reward_notification += "資安研究員 PayPal 帳號資訊尚未收集 -----------------------------\n\n"
        else:
            reward_notification += (
                "資安研究員資料需收集 ------------------------------------------\n\n"
            )

        print("\n「資安研究員獎金紀錄」")
        for key in the_researcher_issues[researcher_email]["rewards"]:
            print(str(the_researcher_issues[researcher_email]["rewards"][key]))
        print("\n「資安研究員獎金總結報告」")
        print(reward_notification)
        all_reward_notifications[researcher_email] = reward_notification
        the_researcher_issues[researcher_email][
            "reward_notification"
        ] = reward_notification
    return the_researcher_issues, all_reward_notifications


def researcher_reward(
    jira,
    jql,
    gsheet,
    salesforce_orgid,
    salesforce_username,
    salesforce_password,
    apphome_data,
    apphome_downloads,
    debugobj=None,
    researcher_email=None,
):
    researcher_issues, reward_notifications = reward(
        jira,
        jql,
        gsheet,
        salesforce_orgid,
        salesforce_username,
        salesforce_password,
        apphome_data,
        apphome_downloads,
        debugobj,
        researcher_email,
    )
    return reward_notifications


def bounty_nomination(
    jira,
    jql,
    gsheet,
    salesforce_orgid,
    salesforce_username,
    salesforce_password,
    apphome_data,
    apphome_downloads,
    debugobj=None,
    researcher_email=None,
):
    researcher_issues, reward_notifications = reward(
        jira,
        jql,
        gsheet,
        salesforce_orgid,
        salesforce_username,
        salesforce_password,
        apphome_data,
        apphome_downloads,
        debugobj,
        researcher_email,
    )
    ### bounty nomination
    # 條件為： 至少一個平台已解 one_fixed == Ture 或 開單超過 90 天 since_submited > 90
    make_gsheet(researcher_issues, gsheet)
