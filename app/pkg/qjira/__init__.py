#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2021-06-05
#
import abc

class i_issue():
    __metaclass__ = abc.ABCMeta
    
    def __init__(self, jira, issue):
        self.jira = jira
        self.issue = issue
        
    @abc.abstractmethod
    def get(self):
        print('Get..')
        return False, u''
        
    @abc.abstractmethod
    def set(self, *args, **kwargs):
        print('Set', args, kwargs)
        
    @abc.abstractmethod
    def disable(self):
        print('Disable..')

    @abc.abstractmethod
    def dump(self):
        print('Dump Data')
        for fid in self.issue.raw['fields']:
            if type(self.issue.raw['fields'][fid]) is list:
                print('--- {fid} is a list'.format(fid=fid))
                if fid=='self.issuelinks':
                    for issue_link in self.issue.raw['fields'][fid]:
                        print('        - {issue_link}'.format(issue_link=issue_link))
            elif type(self.issue.raw['fields'][fid]) is dict:
                print('--- {fid} is a dict'.format(fid=fid))
                if fid=='comment':
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

    def search_blocked_issues(self):
        print('Searching Blocked Issue(s)')
        b_bug_ticket_created = False
        issues = []
        if 'issuelinks' in self.issue.raw['fields']:
            for issue_link in self.issue.raw['fields']['issuelinks']:
                if 'inwardIssue' in issue_link and issue_link['type']['name'] == 'Blocks':
                    blocking_issue = self.jira.issue(issue_link['inwardIssue']['key'])
                    if blocking_issue:
                        print('--- Bug ticket is CREATED at {key}, {summary}'.format(key=blocking_issue.key, summary=blocking_issue.fields.summary))
                        b_bug_ticket_created = True
                        issues.append(blocking_issue)
        if not b_bug_ticket_created:
            print('--- Bug ticket has not been created yet')
        return b_bug_ticket_created, issues
