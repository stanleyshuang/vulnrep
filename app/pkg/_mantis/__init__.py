#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   StanleyS Huang
# Project:  mantisanalyzer 1.1
# Date:     2022-03-18
#
import abc
import os, sys

from mantisconnect2.simple_project import SimpleProject
from mantisconnect2.connector_interface import create_mantis_soap_connector

class i_issue():
    __metaclass__ = abc.ABCMeta
    
    def __init__(self, mantis_url, username, password, project, mantisbt_id, downloads):
        self.mantis_url = mantis_url
        self.username = username
        self.password = password
        self.project = project
        self.mantisbt_id = mantisbt_id
        self.downloads = downloads
        self.diagnostics = None

        self.mc = create_mantis_soap_connector(self.mantis_url+'/api/soap/mantisconnect.php?wsdl')
        if self.mc:
            print("Connent to [{url}], Mantis SOAP MC Version: [{version}]".format(url=self.mantis_url, version=self.mc.version))
        self.mc.set_user_passwd(self.username, self.password)
        self.mc.connect()

        self.issue = self.mc.request_issue_get(self.mantisbt_id)
        # print('Issue #{id} = {issue}'.format(id=self.mantisbt_id, issue=self.issue))

    def get_attachment_list(self):
        attachment_list = []
        for attachment in self.issue.attachments:
            attachment_list.append(attachment)
        return attachment_list

    def open_attachment(self, attachment, file_path='default'):
        content = self.mc.client.service.mc_issue_attachment_get(self.username, self.password, attachment.id)
        if file_path=='default':
            ext_idx = attachment.filename.rfind('.')
            ext = ''
            if ext_idx!=-1:
                ext = attachment.filename[ext_idx:]
            file_path = self.downloads+'/mantis/'+str(self.mantisbt_id)+ext
        open(file_path, 'wb').write(content)

    def enum_issue_fields(self):
        print('Enumerate Issue Fields:')
        for key in self.issue:
            print(str(key) + '\n' + str(self.issue[key]))

    def add_note(self, content):
        '''
        self.mc.client.mc_issue_note_add(
            username=self.username,
            password=self.password,
            issue_id=int(self.mantisbt_id),
            note={
                "text": content
            }
        )
        '''
        pass
