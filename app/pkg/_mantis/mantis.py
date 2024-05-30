#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2021-07-25
#
import json
import zipfile

from pkg._util.util_file import create_folder, get_sub_folder_list
from pkg._util.util_text_file import get_lines
from . import i_issue
from .diagnostics import open_conf, qts_install_time, qpkg_install_time, qpkg_conf_update_info, get_infection_date, raid_metadata

class mantis(i_issue):
    def __init__(self, mantis_url, username, password, project, mantis_id, downloads):
        super(mantis, self).__init__(mantis_url, username, password, project, mantis_id, downloads)
        pass

    def extract_content_for_submission(self):
        summary = self.issue['summary']
        description = self.issue['description']
        additional_information = self.extract_content_from_additional_information()
        (txt_filename, lines) = self.download_extracted_txt()
        return (summary, description, additional_information, txt_filename, lines)

    def extract_content_from_additional_information(self):
        if 'additional_information' in self.issue:
            content = self.issue['additional_information']
            if content is None:
                return ''
            return content
        return ''

    def download_extracted_txt(self):
        attachment_list = self.get_attachment_list()
        path = self.downloads + '/mantis/' + str(self.mantisbt_id)
        create_folder(path)
        for attachment in attachment_list:
            if attachment.filename.find('.txt')!=-1:
                the_file = path + '/' + attachment.filename
                self.open_attachment(attachment, file_path=the_file)
                print('--- open {attachment}'.format(attachment=attachment.filename))
                lines = get_lines(the_file)
                return (the_file, lines)
        return ('', [])


    def download_extracted_diagnostics(self):
        self.diagnostics = []
        attachment_list = self.get_attachment_list()
        for attachment in attachment_list:
            if attachment.filename.find('.zip')!=-1:
                self.open_attachment(attachment)
                # print('--- unzip {attachment}'.format(attachment=self.downloads + '/mantis/' + str(self.mantisbt_id) + '.zip'))
                create_folder(self.downloads + '/mantis/' + str(self.mantisbt_id))
                with zipfile.ZipFile(self.downloads + '/mantis/' + str(self.mantisbt_id) + '.zip', 'r') as zip_ref:
                    zip_ref.extractall(self.downloads + '/mantis/' + str(self.mantisbt_id))
                    self.diagnostics.append(self.downloads + '/mantis/' + str(self.mantisbt_id))
        return self.diagnostics

    def qts_install_time(self, str_incident_date):
        if self.diagnostics is None:
            self.download_extracted_diagnostics()
        if len(self.diagnostics)==0:
            return None
        str_incident_date = get_infection_date(self, str_incident_date)
        return qts_install_time(self.mantisbt_id, self.diagnostics[0], str_incident_date)

    def raid_metadata(self, str_incident_date):
        if self.diagnostics is None:
            self.download_extracted_diagnostics()
        if len(self.diagnostics)==0:
            return None
        str_incident_date = get_infection_date(self, str_incident_date)
        return raid_metadata(self.mantisbt_id, self.diagnostics[0], str_incident_date)

    def qpkg_install_time(self, str_incident_date, qpkg_name_2_versions, qpkg_list, gsheet_v):
        if self.diagnostics is None:
            self.download_extracted_diagnostics()
        if len(self.diagnostics)==0:
            return qpkg_name_2_versions
        str_incident_date = get_infection_date(self, str_incident_date)
        return qpkg_install_time(self.mantisbt_id ,self.diagnostics[0], str_incident_date, qpkg_name_2_versions, qpkg_list, gsheet_v)

    def qpkg_sections(self):
        if self.diagnostics is None:
            self.download_extracted_diagnostics()
        if len(self.diagnostics)==0:
            return None
        the_qpkg_conf = open_conf(self.diagnostics[0], conf_path='/etc/config/qpkg.conf')
        if the_qpkg_conf:
            return the_qpkg_conf.sections()
        return None

    def qpkg_conf_update_info(self):
        if self.diagnostics is None:
            self.download_extracted_diagnostics()
        if len(self.diagnostics)==0:
            return None
        the_qpkg_conf_update_info = qpkg_conf_update_info(self.diagnostics[0])
        if the_qpkg_conf_update_info:
            return the_qpkg_conf_update_info
        return None
