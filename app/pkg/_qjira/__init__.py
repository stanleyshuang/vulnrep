#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2021-06-05
#
import abc


def get_issuetype(issue):
    return issue.fields.issuetype.name


class i_issue:
    __metaclass__ = abc.ABCMeta

    def __init__(self, jira, issue, debug_obj):
        self.jira = jira
        self.issue = issue
        self.debug_obj = debug_obj

        self.b_blocked_run = False
        self.blocked_issues = []
        self.b_blocking_run = False
        self.blocking_issues = []
        self.b_causes_run = False
        self.causes_issues = []
        self.b_clones_run = False
        self.clones_issues = []
        self.b_is_cloned_by_run = False
        self.is_cloned_by_issues = []

        self.b_dependency_traced = False
        self.dependent_counts = 0
        self.dependent_issues = []
        self.b_resolved = False

        self.resolved_counts = 0
        self.resolved_issues = []
        self.unresolved_counts = 0
        self.unresolved_issues = []

    def get_status_name(self):
        return self.issue.fields.status.name.lower()

    def get_time_n_str(
        self, the_time, s_format="%Y-%m-%dT%H:%M:%S.000+0800", local_tz_str="GMT"
    ):
        from datetime import datetime
        from pkg._util.util_datetime import utc_to_local_str

        time = datetime.strptime(the_time, s_format)
        return time, utc_to_local_str(time, local_tz_str, format="%Y-%m-%d")

    def get_created_n_str(self):
        return self.get_time_n_str(self.issue.fields.created)

    def get_auther_and_created_in_changlog(self, field, toStrings):
        achangelog = self.issue.changelog
        for history in achangelog.histories:
            for item in history.items:
                """
                d = {
                    'author': history.author.name,
                    'date': history.created,
                    'field': item.field,
                    'fieldtype' : item.fieldtype,
                    'from': getattr(item, 'from'), # because using item.from doesn't wor
                    'fromString' : item.fromString,
                    'to': item.to,
                    'toString': item.toString
                }
                """
                if field == item.field and item.toString in toStrings:
                    return history.author.name, history.created, item.toString
        return None, None, None

    @abc.abstractmethod
    def set(self, *args, **kwargs):
        print("Set", args, kwargs)

    @abc.abstractmethod
    def set_status(self, raw):
        pass

    @abc.abstractmethod
    def at_completed_states(self):
        return False

    @abc.abstractmethod
    def at_failed_states(self):
        return False

    @abc.abstractmethod
    def run(self, root_issue, parent_issue, data, downloads, b_update=False):
        pass

    @abc.abstractmethod
    def get_gsheet_raw(self):
        return {}

    @abc.abstractmethod
    def trace_dependency(self):
        pass

    def search_blocked(self):
        # print('Searching Blocked Issue(s)')
        if self.b_blocked_run:
            return self.blocked_issues
        self.b_blocked_run = True
        self.blocked_issues = []
        if "issuelinks" in self.issue.raw["fields"]:
            for issue_link in self.issue.raw["fields"]["issuelinks"]:
                if (
                    "inwardIssue" in issue_link
                    and issue_link["type"]["name"] == "Blocks"
                ):
                    blocking_issue = self.jira.issue(
                        issue_link["inwardIssue"]["key"], expand="changelog"
                    )
                    if blocking_issue:
                        # print('--- The issue BLOCKs {key}, {summary}'.format(key=blocking_issue.key, summary=blocking_issue.fields.summary))
                        self.blocked_issues.append(blocking_issue)
        return self.blocked_issues

    def search_blocking(self):
        # print('Searching Blocking Issue(s)')
        if self.b_blocking_run:
            return self.blocking_issues
        self.b_blocking_run = True
        self.blocking_issues = []
        if "issuelinks" in self.issue.raw["fields"]:
            for issue_link in self.issue.raw["fields"]["issuelinks"]:
                if (
                    "outwardIssue" in issue_link
                    and issue_link["type"]["name"] == "Blocks"
                ):
                    blocked_issue = self.jira.issue(
                        issue_link["outwardIssue"]["key"], expand="changelog"
                    )
                    if blocked_issue:
                        # print('--- The issue is BLOCKed {key}, {summary}'.format(key=blocked_issue.key, summary=blocked_issue.fields.summary))
                        self.blocking_issues.append(blocked_issue)
        return self.blocking_issues

    def search_causes(self):
        # print('Searching Causes Issue(s)')
        if self.b_causes_run:
            return self.causes_issues
        self.b_causes_run = True
        self.causes_issues = []
        if "issuelinks" in self.issue.raw["fields"]:
            for issue_link in self.issue.raw["fields"]["issuelinks"]:
                if (
                    "outwardIssue" in issue_link
                    and issue_link["type"]["name"] == "Problem/Incident"
                ):
                    blocked_issue = self.jira.issue(
                        issue_link["outwardIssue"]["key"], expand="changelog"
                    )
                    if blocked_issue:
                        # print('--- The issue CAUSES {key}, {summary}'.format(key=blocked_issue.key, summary=blocked_issue.fields.summary))
                        self.causes_issues.append(blocked_issue)
        return self.causes_issues

    def search_clones(self):
        # print('Searching Clones Issue(s)')
        if self.b_clones_run:
            return self.clones_issues
        self.b_clones_run = True
        self.clones_issues = []
        if "issuelinks" in self.issue.raw["fields"]:
            for issue_link in self.issue.raw["fields"]["issuelinks"]:
                if (
                    "outwardIssue" in issue_link
                    and issue_link["type"]["name"] == "Cloners"
                ):
                    the_issue = self.jira.issue(
                        issue_link["outwardIssue"]["key"], expand="changelog"
                    )
                    if the_issue:
                        # print('--- The issue CLONES {key}, {summary}'.format(key=the_issue.key, summary=the_issue.fields.summary))
                        self.clones_issues.append(the_issue)
        return self.clones_issues

    def search_is_cloned_by(self):
        # print('Searching Clones Issue(s)')
        if self.b_is_cloned_by_run:
            return self.is_cloned_by_issues
        self.b_is_cloned_by_run = True
        self.is_cloned_by_issues = []
        if "issuelinks" in self.issue.raw["fields"]:
            for issue_link in self.issue.raw["fields"]["issuelinks"]:
                if (
                    "inwardIssue" in issue_link
                    and issue_link["type"]["name"] == "Cloners"
                ):
                    the_issue = self.jira.issue(
                        issue_link["inwardIssue"]["key"], expand="changelog"
                    )
                    if the_issue:
                        # print('--- The issue IS CLONED BY {key}, {summary}'.format(key=the_issue.key, summary=the_issue.fields.summary))
                        self.is_cloned_by_issues.append(the_issue)
        return self.is_cloned_by_issues

    @abc.abstractmethod
    def dump(self):
        print("Dump Data")
        for fid in self.issue.raw["fields"]:
            if type(self.issue.raw["fields"][fid]) is list:
                print("--- {fid} is a list".format(fid=fid))
                # if fid in ['issuelinks', 'labels']:
                for item in self.issue.raw["fields"][fid]:
                    print("        - {item}".format(item=item))
            elif type(self.issue.raw["fields"][fid]) is dict:
                print("--- {fid} is a dict".format(fid=fid))
                # if fid in ['comment', 'resolution', 'status']:
                for n, k in enumerate(self.issue.raw["fields"][fid]):
                    print(
                        "        - {n}:{k}-{v}".format(
                            n=n, k=k, v=self.issue.raw["fields"][fid][k]
                        )
                    )
            elif self.issue.raw["fields"][fid]:
                print(
                    "--- {fid} {name}".format(
                        fid=fid, name=self.issue.raw["fields"][fid]
                    )
                )

        print("--- comment")
        comments = self.issue.fields.comment.comments
        for comment in comments:
            cid = comment.id
            author = comment.author.displayName
            time = comment.created
            body = comment.body.replace("\r", " ").replace("\n", " ")
            print(
                "        - {cid}: {author} {time}\n      {body}".format(
                    cid=cid, author=author, time=time, body=body
                )
            )
        status = self.issue.fields.status.name
        print("--- status {status}".format(status=status))

        changelog = []
        achangelog = self.issue.changelog
        for history in achangelog.histories:
            for item in history.items:
                d = {
                    "author": history.author.name,
                    "date": history.created,
                    "field": item.field,
                    "fieldtype": item.fieldtype,
                    "from": getattr(
                        item, "from"
                    ),  # because using item.from doesn't wor
                    "fromString": item.fromString,
                    "to": item.to,
                    "toString": item.toString,
                }
                print(d)
                changelog.append(d)
        print("--- attachements")
        for attachment in self.issue.fields.attachment:
            image = attachment.get()
            print(
                "    {attachment} {id}".format(
                    attachment=attachment.filename, id=attachment.id
                )
            )

    def download_attachments(self, downloads, filter):
        download_files = []
        for attachment in self.issue.fields.attachment:
            if not filter(attachment.filename):
                continue
            image = attachment.get()
            jira_filename = (
                downloads + "/jira/" + self.issue.key + "/" + attachment.filename
            )
            download_files.append(jira_filename)
            with open(jira_filename, "wb") as f:
                f.write(image)
        return download_files

    def remove_attachments(self, filter):
        for attachment in self.issue.fields.attachment:
            if not filter(attachment.filename):
                continue
            self.jira.delete_attachment(attachment.id)

    def debuglog_r(self, message, since=None):
        if since:
            from datetime import datetime
            from pkg._util.util_datetime import duration_days

            now = datetime.now()
            self.debug_obj.log_r(message + " (" + str(duration_days(since, now)) + ")")
        else:
            self.debug_obj.log_r(message)

    def debuglog_i(self, message, since=None):
        if since:
            from datetime import datetime
            from pkg._util.util_datetime import duration_days

            now = datetime.now()
            self.debug_obj.log_i(message + " (" + str(duration_days(since, now)) + ")")
        else:
            self.debug_obj.log_i(message)

    def debuglog_v(self, message, since=None):
        if since:
            from datetime import datetime
            from pkg._util.util_datetime import duration_days

            now = datetime.now()
            self.debug_obj.log_v(message + " (" + str(duration_days(since, now)) + ")")
        else:
            self.debug_obj.log_v(message)

    def add_component(self, componentname):
        ### Add componentname in components
        b_vulnerability_report = False
        existingComponents = []
        for component in self.issue.fields.components:
            existingComponents.append({"name": component.name})
            if component.name == componentname:
                b_vulnerability_report = True
        if not b_vulnerability_report:
            existingComponents.append({"name": componentname})
            try:
                self.issue.update(fields={"components": existingComponents})
            except:
                self.debuglog_r(
                    "xxx Add Components Failed: {component} at {key}".format(
                        component=componentname, key=self.issue.key
                    )
                )

    def does_component_exist(self, componentname):
        ### Add componentname in components
        for component in self.issue.fields.components:
            if component.name == componentname:
                return True
        return False

    def update_labels(self, the_label):
        labels = self.issue.fields.labels
        if the_label not in labels:
            labels.append(the_label)
            self.issue.update(fields={"labels": labels})

    def remove_label(self, the_label):
        labels = self.issue.fields.labels
        if the_label in labels:
            labels.remove(the_label)
            self.issue.update(fields={"labels": labels})

    def does_label_exist(self, the_label):
        return the_label in self.issue.fields.labels

    @abc.abstractmethod
    def find_task(self):
        pass

    @staticmethod
    def issue_filter(jira, jql):
        todo_issues = set()
        maxResults = 50
        got = maxResults
        total = 0
        while got == maxResults:
            print("    TOTAL issues: [" + str(total) + "] on JQL:[" + jql + "]")
            issues = jira.search_issues(jql, startAt=total, maxResults=maxResults)
            for an_issue in issues:
                print(
                    "      [{key}]{summary} - [{updated}]".format(
                        key=an_issue.key,
                        summary=an_issue.fields.summary,
                        updated=an_issue.fields.updated[11:19],
                    )
                )
                todo_issues.add(an_issue)
            got = len(issues)
            total += got
        return todo_issues

    @staticmethod
    def add_watchers(jira, issue, watchers):
        current_watchers = jira.watchers(issue)
        current_watchers_name = []
        for watcher in current_watchers.watchers:
            current_watchers_name.append(watcher.name)
        # print('current_watchers_name = '+str(current_watchers_name))
        """
        print("Issue has {} watcher(s)".format(watcher.watchCount))
        for watcher in current_watchers.watchers:
            print(watcher)
            print(watcher.name)
            # watcher is instance of jira.resources.User:
            print(watcher.emailAddress)
        """
        for watcher_name in watchers:
            try:
                watcher = jira.user(watcher_name)
                if watcher.name not in current_watchers_name:
                    # print('   [{issuekey}] add watcher: {watcher}'.format(issuekey=issue.id, watcher=watcher))
                    jira.add_watcher(issue.id, watcher.name)
            except Exception as e:
                print("    " + str(e))
