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

class i_issue():
    __metaclass__ = abc.ABCMeta
    
    def __init__(self, jira, issue):
        self.jira = jira
        self.issue = issue

        self.b_blocked_run = False
        self.blocked_issues = []

        self.b_blocking_run = False
        self.blocking_issues = []

        self.b_unresolved_run = False
        self.unresolved_counts = 0
        self.unresolved_issues = []
        
    def get_status_name(self):
        return self.issue.fields.status.name.lower()

    def get_auther_and_created_in_changlog(self, field, toStrings):
        achangelog = self.issue.changelog
        for history in achangelog.histories:
            for item in history.items:
                '''
                d = {
                    'author': history.author.displayName,
                    'date': history.created,
                    'field': item.field,
                    'fieldtype' : item.fieldtype,
                    'from': getattr(item, 'from'), # because using item.from doesn't wor
                    'fromString' : item.fromString,
                    'to': item.to,
                    'toString': item.toString
                }
                '''
                if field==item.field and item.toString in toStrings:
                    return history.author.displayName, history.created, item.toString
        return None, None, None
        
    @abc.abstractmethod
    def set(self, *args, **kwargs):
        print('Set', args, kwargs)
        
    @abc.abstractmethod
    def resolved(self):
        return False
        
    @abc.abstractmethod
    def run(self, downloads, b_update=False):
        print('Run')

    @abc.abstractmethod
    def collect_unresolved_issues(self):
        '''
        self.b_unresolved_run:  True or False
        self.unresolved_counts: The number of unsolved issues
        self.unresolved_issues: [{
                                    'key':          jira key, 'INTSI000-1033',
                                    'created':      date time in format '2021-05-13',
                                    'issuetype':    'Bug', 'App Release Process' or 'FW Release Process',
                                    'status':       'done', 'verified', and so on,
                                    'summary':      jira summary,
                                    'eta':          date time in format '2021-05-13',
                                }]
        '''
        pass
    
    def search_blocked(self):
        # print('Searching Blocked Issue(s)')
        if self.b_blocked_run:
            return self.blocked_issues
        self.b_blocked_run = True
        self.blocked_issues = []
        if 'issuelinks' in self.issue.raw['fields']:
            for issue_link in self.issue.raw['fields']['issuelinks']:
                if 'inwardIssue' in issue_link and issue_link['type']['name'] == 'Blocks':
                    blocking_issue = self.jira.issue(issue_link['inwardIssue']['key'], expand='changelog')
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
        if 'issuelinks' in self.issue.raw['fields']:
            for issue_link in self.issue.raw['fields']['issuelinks']:
                if 'outwardIssue' in issue_link and issue_link['type']['name'] == 'Blocks':
                    blocked_issue = self.jira.issue(issue_link['outwardIssue']['key'], expand='changelog')
                    if blocked_issue:
                        # print('--- The issue is BLOCKed {key}, {summary}'.format(key=blocked_issue.key, summary=blocked_issue.fields.summary))
                        self.blocking_issues.append(blocked_issue)
        return self.blocking_issues

    @abc.abstractmethod
    def dump(self):
        print('Dump Data')
        for fid in self.issue.raw['fields']:
            if type(self.issue.raw['fields'][fid]) is list:
                print('--- {fid} is a list'.format(fid=fid))
                if fid=='issuelinks':
                    for issue_link in self.issue.raw['fields'][fid]:
                        print('        - {issue_link}'.format(issue_link=issue_link))
            elif type(self.issue.raw['fields'][fid]) is dict:
                print('--- {fid} is a dict'.format(fid=fid))
                if fid in ['comment', 'resolution', 'status']:
                    for n, v in enumerate(self.issue.raw['fields'][fid]):
                        print('        - {n}:{v}'.format(n=n, v=v))
            elif self.issue.raw['fields'][fid]:
                print('--- {fid} {name}'.format(fid=fid, name=self.issue.raw['fields'][fid]))

        print('--- comment')
        comments = self.issue.fields.comment.comments
        for comment in comments:
            cid = comment.id
            author = comment.author.displayName
            time = comment.created
            body = comment.body.replace("\r", " ").replace("\n", " ")
            print('        - {cid}: {author} {time}\n      {body}'.format(cid=cid, author=author, time=time, body=body))
        status = self.issue.fields.status.name
        print('--- status {status}'.format(status=status))

        changelog = []
        achangelog = self.issue.changelog
        for history in achangelog.histories:
            for item in history.items:
                d = {
                    'author': history.author.displayName,
                    'date': history.created,
                    'field': item.field,
                    'fieldtype' : item.fieldtype,
                    'from': getattr(item, 'from'), # because using item.from doesn't wor
                    'fromString' : item.fromString,
                    'to': item.to,
                    'toString': item.toString
                }
                print(d)
                changelog.append(d)
        print('--- attachements')
        for attachment in self.issue.fields.attachment:    
            image = attachment.get()
            print('    {attachment} {id}'.format(attachment=attachment.filename, id=attachment.id))

    def download_attachments(self, downloads, filter):
        download_files = []
        for attachment in self.issue.fields.attachment:
            if not filter(attachment.filename):
                continue
            image = attachment.get()
            jira_filename = downloads + '/' + attachment.filename
            download_files.append(jira_filename)
            with open(jira_filename, 'wb') as f:        
                f.write(image)
        return download_files

    def remove_attachments(self, filter):
        for attachment in self.issue.fields.attachment:
            if not filter(attachment.filename):
                continue
            self.jira.delete_attachment(attachment.id)

