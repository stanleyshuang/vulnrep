#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  gsheet_vulnrep 1.0
# Date:     2021-07-15
#
from pkg._gsheet import i_gsheet


ATASK_REWARDPROPOSED_IDX = 12
ATASK_NOTESSUBMITTED_IDX = 13
ATASK_PAYMENTSUBMITTED_IDX = 14
ATASK_PAYMENTPRINTED_IDX = 15

BOUNTYHUNTER_CREDIT_IDX = 5

BOUNTYNOMINATION_REWARD_IDX = 4
BOUNTYNOMINATION_SESSION_IDX = 11
BOUNTYNOMINATION_DOCUSIGN_IDX = 12
BOUNTYNOMINATION_NOTES_IDX = 13

QSA_QSAID_IDX = 3
QSA_REVIEWED_IDX = 9
QSA_PUBLISHED_IDX = 10


class gsheet_vulnrep(i_gsheet):
    def __init__(self, the_credential, the_key, url):
        super(gsheet_vulnrep, self).__init__(the_credential, the_key, url)
        self.b_personal_data_collected = False

    def retrieve_qsa_credit(self, issue_key, qsa):
        """
        把 bountyhunter 的 'credit' (BOUNTYHUNTER_CREDIT_IDX) 貼在 qsa['gsheet']['credit'] 傳出來。
        """
        if (
            "task" in qsa
            and "researcher_email" in qsa["task"]
            and qsa["task"]["researcher_email"]
            and len(qsa["task"]["researcher_email"]) > 0
        ):
            researcher_email = qsa["task"]["researcher_email"]
        else:
            return qsa
        """
        gsheet_obj['credit']
        """
        ### 確定 qsa 中，有 gsheet 階層
        if "gsheet" not in qsa:
            qsa["gsheet"] = {}
        gsheet_obj = qsa["gsheet"]

        ### 指定 gsheet 階層的參數
        worksheet_name = "bountyhunter"
        worksheet = self.get_sheet(worksheet_name)
        recs = self.search_records_1(3, researcher_email, worksheet)
        if len(recs) == 0:
            # print('Jira key {issue_key} not found'.format(issue_key=issue_key))
            gsheet_obj["credit"] = None
        elif len(recs) == 1:
            # print('Jira key {issue_key} found at {row}, updating..'.format(issue_key=issue_key, row=recs[0][0]))
            row = recs[0][0]
            rec_data = recs[0][1]
            if rec_data and len(rec_data) > BOUNTYHUNTER_CREDIT_IDX:
                # print('Credit = {credit}'.format(credit=rec_data[BOUNTYHUNTER_CREDIT_IDX]))
                gsheet_obj["credit"] = rec_data[BOUNTYHUNTER_CREDIT_IDX]
            else:
                gsheet_obj["credit"] = None
        else:
            # print('Jira key {issue_key} are more than one record'.format(issue_key=issue_key))
            for rec in recs:
                pass

        ### 將 qsa 位址回傳
        return qsa

    def update_researcher(self, sf_data):
        """
        把 sf_data 裡，researcher sf 開單日期，名字，信箱，更新 gsheet bountyhunter。
        """
        if (
            sf_data is None
            or "researcher_email" not in sf_data
            or len(sf_data["researcher_email"]) == 0
        ):
            self.b_personal_data_collected = False
            return
        worksheet_name = "bountyhunter"
        worksheet = self.get_sheet(worksheet_name)
        researcher_rec = [
            sf_data["created_date"],
            sf_data["researcher_name"],
            sf_data["researcher_email"],
        ]
        num_found = self.search_n_update(
            3, sf_data["researcher_email"], researcher_rec, worksheet
        )
        if num_found == 0:
            self.b_personal_data_collected = False
        elif num_found == 1:
            self.b_personal_data_collected = True
        else:
            pass

    def read_bountyhunter_json(self, sf_data):
        """
        把 sf_data 裡，信箱相同的 bountyhunter 讀出成 json 格式。
        """
        if (
            sf_data is None
            or "researcher_email" not in sf_data
            or len(sf_data["researcher_email"]) == 0
        ):
            return None
        worksheet_name = "bountyhunter"
        worksheet = self.get_sheet(worksheet_name)
        recs = self.search_records_1(3, sf_data["researcher_email"], worksheet)
        if len(recs) == 0:
            return None
        elif len(recs) == 1:
            BOUNTYHUNTER_COUNTRY_IDX = 3
            if len(recs[0][1]) > BOUNTYHUNTER_COUNTRY_IDX:
                return {
                    "bountyhunter1": recs[0][1][:BOUNTYHUNTER_COUNTRY_IDX],
                    "bountyhunter2": recs[0][1][BOUNTYHUNTER_COUNTRY_IDX:],
                }
            else:
                return {
                    "bountyhunter1": recs[0][1],
                }
        else:
            return None

    def batch_get_reward_draft_n_reward(self, issues):
        """
        將 issues 裡 key 相同，在 bounty_nomination 中，Notes ($M) 的值批次儲存在 proposal_draft 傳出。
        """
        worksheet_name = "bounty_nomination"
        worksheet = self.get_sheet(worksheet_name)

        jirakeys = []
        for issue in issues:
            ### get key
            jirakeys.append(issue.issue.key)

        proposal_draft = {}
        reward = {}
        the_group_recs = self.batch_search_records_1(7, jirakeys, worksheet)
        for jirakey in the_group_recs:
            recs = the_group_recs[jirakey]
            if len(recs) == 0:
                proposal_draft[jirakey] = None
                reward[jirakey] = None
            elif len(recs) == 1:
                row = recs[0][0]
                rec_data = recs[0][1]
                if len(rec_data) <= BOUNTYNOMINATION_NOTES_IDX:
                    proposal_draft[jirakey] = None
                else:
                    proposal_draft[jirakey] = rec_data[BOUNTYNOMINATION_NOTES_IDX]
                if len(rec_data) <= BOUNTYNOMINATION_REWARD_IDX:
                    reward[jirakey] = None
                else:
                    reward[jirakey] = rec_data[BOUNTYNOMINATION_REWARD_IDX]
            else:
                for rec in recs:
                    print(
                        "!!! EXCEPTION: multiple reward found {row}, {values_list}".format(
                            row=rec[0], values_list=str(rec[1])
                        )
                    )
                proposal_draft[jirakey] = None
                reward[jirakey] = None
        return proposal_draft, reward

    """
    def set_proposed_reward(self, issue, reward):
        # 將 issue key 設定 reward。如已有值不覆寫。
        worksheet_name = 'atask'
        worksheet = self.get_sheet(worksheet_name)

        url = self.url + '/browse/' + issue.issue.key

        recs = self.search_records_1(6, url, worksheet)
        if len(recs)==0:
            return
        elif len(recs)==1:
            row = recs[0][0]
            rec_data = recs[0][1]
            print('>>> SET REWARD {key} {reward}'.format(key=issue.issue.key, reward=reward))
            if len(rec_data)>ATASK_REWARDPROPOSED_IDX and len(rec_data[ATASK_REWARDPROPOSED_IDX])<=0:
                rec_data[ATASK_REWARDPROPOSED_IDX] = reward
                num_found = self.search_n_update(6, url, rec_data, worksheet, no_overwrite_idxs=[ATASK_REWARDPROPOSED_IDX])
            elif len(rec_data)<=ATASK_REWARDPROPOSED_IDX:
                rec_data = rec_data + [None] * (ATASK_REWARDPROPOSED_IDX + 1 - len(rec_data))
                rec_data[ATASK_REWARDPROPOSED_IDX] = reward
                num_found = self.search_n_update(6, url, rec_data, worksheet, no_overwrite_idxs=[ATASK_REWARDPROPOSED_IDX])
        else:
            for rec in recs:
                print('!!! EXCEPTION: multiple reward found {row}, {values_list}'.format(row=rec[0], values_list=str(rec[1])))
    """

    def set_notes_submitted_date(self, issue, notes_date_str):
        """
        將 issues 裡 key 相同，在 atask 中，送簽 - 13 ($N) 的值覆寫為 notes_date_str。
        """
        worksheet_name = "atask"
        worksheet = self.get_sheet(worksheet_name)

        url = self.url + "/browse/" + issue.issue.key

        recs = self.search_records_1(6, url, worksheet)
        if len(recs) == 0:
            return
        elif len(recs) == 1:
            row = recs[0][0]
            rec_data = recs[0][1]
            print(
                ">>> SET NOTES SUBMITTED DATE {key} {notes_date_str}".format(
                    key=issue.issue.key, notes_date_str=notes_date_str
                )
            )
            if (
                len(rec_data) > ATASK_NOTESSUBMITTED_IDX
                and len(rec_data[ATASK_NOTESSUBMITTED_IDX]) <= 0
            ):
                rec_data[ATASK_NOTESSUBMITTED_IDX] = notes_date_str
                num_found = self.search_n_update(6, url, rec_data, worksheet)
            elif len(rec_data) <= ATASK_NOTESSUBMITTED_IDX:
                rec_data = rec_data + [None] * (
                    ATASK_NOTESSUBMITTED_IDX + 1 - len(rec_data)
                )
                rec_data[ATASK_NOTESSUBMITTED_IDX] = notes_date_str
                num_found = self.search_n_update(6, url, rec_data, worksheet)
        else:
            for rec in recs:
                print(
                    "!!! EXCEPTION: multiple records found {row}, {values_list}".format(
                        row=rec[0], values_list=str(rec[1])
                    )
                )

    def a_task(self, issue, raw):
        """
        更新 atask
        """
        worksheet_name = "atask"
        worksheet = self.get_sheet(worksheet_name)
        url = self.url + "/browse/" + issue.key
        a_task = [
            raw["done"],  # resolved or not
            raw["dependency_resolved"],  # dependency resolved or not
            raw["researcher_email"],
            raw["sf_created"],
            raw["sf_case_num"],
            url,
        ]
        if "cveid" in raw:
            a_task.append(raw["cveid"])
        num_found = self.search_n_update(6, url, a_task, worksheet)

    def read_atask_json(self, issuekey):
        """
        把 atask 存成 fdb 物件
        """
        worksheet_name = "atask"
        worksheet = self.get_sheet(worksheet_name)
        url = self.url + "/browse/" + issuekey
        recs = self.search_records_1(6, url, worksheet)
        ATASK_SADRAFT_IDX = 7
        if len(recs) == 0:
            return {}
        elif len(recs) == 1:
            return {
                "atask1": recs[0][1][:ATASK_SADRAFT_IDX],
                "atask2": recs[0][1][ATASK_SADRAFT_IDX:],
            }
        else:
            return {}

    def compose_atask_json(self, issuekey, raw):
        """
        把 raw 存成 fdb 物件
        """
        url = self.url + "/browse/" + issuekey
        a_task = [
            raw["done"],  # resolved or not
            raw["dependency_resolved"],  # dependency resolved or not
            raw["researcher_email"],
            raw["sf_created"],
            raw["sf_case_num"],
            url,
        ]
        if "severity_level" in raw:
            a_task.append(raw["cveid"])
        return {"atask1": a_task}

    def update_v5(self, raw):
        """
        更新 v5
        """
        worksheet_name = "v5"
        worksheet = self.get_sheet(worksheet_name)

        product = raw[0]
        version = raw[1]
        qsaid = raw[2]
        cveid = raw[3]
        jirakey = raw[4]
        filters = {1: product, 2: version, 3: qsaid, 4: cveid, 5: jirakey}
        num_found = self.search_n_update_n(filters, raw, worksheet)

    def search_v5(self, raw):
        """
        搜尋符合條件的 v5
        """
        worksheet_name = "v5"
        worksheet = self.get_sheet(worksheet_name)

        product = raw[0]
        version = raw[1]
        qsaid = raw[2]
        cveid = raw[3]
        jirakey = raw[4]
        filters = {1: product, 2: version, 3: qsaid, 4: cveid, 5: jirakey}
        recs = self.search_records_n(filters, worksheet)
        if len(recs) == 0:
            return None
        elif len(recs) == 1:
            # merged = i_gsheet.merge_rec(recs[0][1], raw)
            # worksheet.update('A{row}:{col}{row}'.format(row=recs[0][0], col=self.cal_col_by_len(len(merged))), [merged])
            return [recs[0][1]]
        else:
            results = []
            for item in recs:
                results.append(item[1])
            return results

    def dump_v5(self):
        return self.get_records(sheet="v5")

    def available_qsa_id(self):
        """
        搜尋 qsa_dashboard
        """
        worksheet_name = "qsa"
        lists = self.get_records(sheet=worksheet_name)
        qsa_set = set()
        for the_list in lists:
            if the_list[3]:
                qsa_set.add(the_list[3])
        for idx in range(1, len(qsa_set) + 1):
            available_qsaid = "QSA-24-" + "{:02d}".format(idx)
            if available_qsaid not in qsa_set:
                return available_qsaid
        return "QSA-24-" + "{:02d}".format(len(qsa_set) + 1)

    def search_qsa_dashboard(self, jira_key):
        """
        搜尋 qsa_dashboard
        """
        worksheet_name = "qsa"
        worksheet = self.get_sheet(worksheet_name)

        filters = {
            2: jira_key,
        }
        origin = self.search_records_n(filters, worksheet)
        if len(origin) == 0:
            return None
        elif len(origin) == 1:
            return origin[0][1]
        else:
            results = []
            for item in origin:
                results.append(item[1])
            return results

    def update_qsa_dashboard(self, qsa_dashboard):
        """
        更新 qsa_dashboard
        """
        worksheet_name = "qsa"
        worksheet = self.get_sheet(worksheet_name)

        jira_key = qsa_dashboard[1]
        filters = {
            2: jira_key,
        }
        origin = self.search_records_n(filters, worksheet)
        if len(origin) == 0:
            num_found = self.search_n_update_n(filters, qsa_dashboard, worksheet)
            print("~~~ Append " + str(qsa_dashboard))
        elif len(origin) == 1:
            if len(origin[0][1]) < len(qsa_dashboard):
                num_found = self.search_n_update_n(
                    filters,
                    qsa_dashboard,
                    worksheet,
                    no_overwrite_idxs=[
                        QSA_QSAID_IDX,
                        QSA_REVIEWED_IDX,
                        QSA_PUBLISHED_IDX,
                    ],
                )
                print("~~~ Modify " + str(qsa_dashboard))
            else:
                for i in range(1, len(qsa_dashboard)):
                    if (
                        i not in [QSA_QSAID_IDX, QSA_REVIEWED_IDX, QSA_PUBLISHED_IDX]
                        and origin[0][1][i] != qsa_dashboard[i]
                        and len(qsa_dashboard[i]) > 0
                    ):
                        num_found = self.search_n_update_n(
                            filters,
                            qsa_dashboard,
                            worksheet,
                            no_overwrite_idxs=[
                                QSA_QSAID_IDX,
                                QSA_REVIEWED_IDX,
                                QSA_PUBLISHED_IDX,
                            ],
                        )
                        print("~~~ Modify " + str(qsa_dashboard))
                        break

    def update_release_note(self, release_note):
        """
        更新 release_note
        """
        worksheet_name = "release_note"
        worksheet = self.get_sheet(worksheet_name)

        product = release_note[1]
        filters = {
            2: product,
        }
        origin = self.search_records_n(filters, worksheet)
        if len(origin) == 0:
            num_found = self.search_n_update_n(filters, release_note, worksheet)
            print("~~~ Append " + str(release_note))
        elif len(origin) == 1:
            if len(origin[0][1]) < len(release_note):
                num_found = self.search_n_update_n(
                    filters, release_note, worksheet, no_overwrite_idxs=[]
                )
                print("~~~ Modify " + str(release_note))
            else:
                for i in range(1, len(release_note)):
                    if (
                        i not in []
                        and origin[0][1][i] != release_note[i]
                        and len(release_note[i]) > 0
                    ):
                        num_found = self.search_n_update_n(
                            filters, release_note, worksheet, no_overwrite_idxs=[]
                        )
                        print("~~~ Modify " + str(release_note))
                        break

    def update_overdue(self, the_record, worksheet_name="overdue"):
        """
        更新 the_record
        """
        worksheet = self.get_sheet(worksheet_name)

        jirakey = the_record[1]
        filters = {
            2: jirakey,
        }
        origin = self.search_records_n(filters, worksheet)
        if len(origin) == 0:
            num_found = self.search_n_update_n(filters, the_record, worksheet)
            print("~~~ Append " + str(the_record))
        elif len(origin) == 1:
            if len(origin[0][1]) < len(the_record):
                num_found = self.search_n_update_n(
                    filters, the_record, worksheet, no_overwrite_idxs=[]
                )
                print("~~~ Modify " + str(the_record))
            else:
                for i in range(1, len(the_record)):
                    if (
                        i not in []
                        and origin[0][1][i] != the_record[i]
                        and len(the_record[i]) > 0
                    ):
                        num_found = self.search_n_update_n(
                            filters, the_record, worksheet, no_overwrite_idxs=[]
                        )
                        print("~~~ Modify " + str(the_record))
                        break

    def update_bounty_nomination(self, bounty_nomination):
        """
        更新 bounty_nomination
        """
        worksheet_name = "bounty_nomination"
        worksheet = self.get_sheet(worksheet_name)

        sf_case_num = bounty_nomination[5]
        jira_key = bounty_nomination[6]
        filters = {
            6: sf_case_num,
            7: jira_key,
        }
        origin = self.search_records_n(filters, worksheet)
        if len(origin) == 0:
            num_found = self.search_n_update_n(filters, bounty_nomination, worksheet)
            print("~~~ Append " + str(bounty_nomination))
        elif len(origin) == 1:
            if len(origin[0][1]) < len(bounty_nomination):
                num_found = self.search_n_update_n(
                    filters,
                    bounty_nomination,
                    worksheet,
                    no_overwrite_idxs=[
                        BOUNTYNOMINATION_REWARD_IDX,
                        BOUNTYNOMINATION_SESSION_IDX,
                        BOUNTYNOMINATION_DOCUSIGN_IDX,
                        BOUNTYNOMINATION_NOTES_IDX,
                    ],
                )
                print("~~~ Modify " + str(bounty_nomination))
            else:
                for i in range(1, len(bounty_nomination)):
                    if (
                        i
                        not in [
                            BOUNTYNOMINATION_REWARD_IDX,
                            BOUNTYNOMINATION_SESSION_IDX,
                            BOUNTYNOMINATION_DOCUSIGN_IDX,
                            BOUNTYNOMINATION_NOTES_IDX,
                        ]
                        and origin[0][1][i] != bounty_nomination[i]
                        and len(bounty_nomination[i]) > 0
                    ):
                        num_found = self.search_n_update_n(
                            filters,
                            bounty_nomination,
                            worksheet,
                            no_overwrite_idxs=[
                                BOUNTYNOMINATION_REWARD_IDX,
                                BOUNTYNOMINATION_SESSION_IDX,
                                BOUNTYNOMINATION_DOCUSIGN_IDX,
                                BOUNTYNOMINATION_NOTES_IDX,
                            ],
                        )
                        print("~~~ Modify " + str(bounty_nomination))
                        break

    def update_triage(self, triage):
        """
        更新 triage
        """
        worksheet_name = "triage"
        worksheet = self.get_sheet(worksheet_name)

        sf_case_num = triage[13]
        jira_key = triage[14]
        filters = {
            14: sf_case_num,
            15: jira_key,
        }
        origin = self.search_records_n(filters, worksheet)
        if len(origin) == 0:
            num_found = self.search_n_update_n(filters, triage, worksheet)
            print("~~~ Append " + str(triage))
        elif len(origin) == 1:
            if len(origin[0][1]) < len(triage):
                num_found = self.search_n_update_n(
                    filters,
                    triage,
                    worksheet,
                    no_overwrite_idxs=[],
                )
                print("~~~ Modify " + str(triage))
            else:
                for i in range(1, len(triage)):
                    if (
                        i not in []
                        and origin[0][1][i] != triage[i]
                        and (isinstance(triage[i], str) and len(triage[i]) > 0)
                    ):
                        num_found = self.search_n_update_n(
                            filters,
                            triage,
                            worksheet,
                            no_overwrite_idxs=[],
                        )
                        print("~~~ Modify " + str(triage))
                        break
