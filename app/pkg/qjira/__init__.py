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
        self.b_blocked_exist = False
        self.blocked_issues = []

        self.b_blocking_run = False
        self.b_blocking = False
        self.blocking_issues = []

        self.b_solved_run = False
        self.b_solved = False
        self.unresolved_counts = 0
        self.unresolved_issues = []

        self.author = ''
        self.str_created = ''
        self.status = ''
        
    def get_status(self):
        return self.issue.fields.status.name
        
    @abc.abstractmethod
    def set(self, *args, **kwargs):
        print('Set', args, kwargs)

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
    
    @abc.abstractmethod
    def search_blocked(self):
        print('Searching Blocked Issue(s)')
        if self.b_blocked_run:
            return self.b_blocked_exist, self.blocked_issues
        self.b_blocked_run = True
        self.b_blocked_exist = False
        self.blocked_issues = []
        if 'issuelinks' in self.issue.raw['fields']:
            for issue_link in self.issue.raw['fields']['issuelinks']:
                if 'inwardIssue' in issue_link and issue_link['type']['name'] == 'Blocks':
                    blocking_issue = self.jira.issue(issue_link['inwardIssue']['key'], expand='changelog')
                    if blocking_issue:
                        print('--- The issue BLOCKs {key}, {summary}'.format(key=blocking_issue.key, summary=blocking_issue.fields.summary))
                        self.b_blocked_exist = True
                        self.blocked_issues.append(blocking_issue)
        if not self.b_blocked_exist:
            print('--- There is no blocking issue')
        return self.b_blocked_exist, self.blocked_issues

    @abc.abstractmethod
    def search_blocking(self):
        print('Searching Blocking Issue(s)')
        if self.b_blocking_run:
            return self.b_blocking, self.blocking_issues
        self.b_blocking_run = True
        self.b_blocking = False
        self.blocking_issues = []
        if 'issuelinks' in self.issue.raw['fields']:
            for issue_link in self.issue.raw['fields']['issuelinks']:
                if 'outwardIssue' in issue_link and issue_link['type']['name'] == 'Blocks':
                    blocked_issue = self.jira.issue(issue_link['outwardIssue']['key'], expand='changelog')
                    if blocked_issue:
                        print('--- The issue is BLOCKed {key}, {summary}'.format(key=blocked_issue.key, summary=blocked_issue.fields.summary))
                        self.b_blocking = True
                        self.blocking_issues.append(blocked_issue)
        if not self.b_blocking:
            print('--- There is blocking no issue')
        return self.b_blocking, self.blocking_issues
        
    @abc.abstractmethod
    def resolved(self):
        '''
        b_solved_run:       True or False
        unresolved_counts:  The number of unsolved issues
        unresolved_issues:  [{
                                'key':      jira key
                                'summary':  jira summary,
                                'created':  date time in format '2021-05-13',
                                'eta':      date time in format '2021-05-13',
                            }]
        '''
        return self.b_solved, self.unresolved_counts, self.unresolved_issues

    def get_change_auther_and_created(self, field, toStrings):
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
        
