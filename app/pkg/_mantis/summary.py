#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  mantisanalysis 1.0
# Date:     2021-11-27
#
import json
import re
import os

from .mantis import mantis
from pkg._mantis.diagnostics import qts_install_time, qpkg_install_time, open_conf, qpkg_conf_update_info, raid_metadata, get_infection_date
from pkg._util import util_globalvar
from pkg._util.util_text_file import get_lines
from pkg._util.util_file import get_sub_folder_list, get_name_list_of_files

def summarize_qts_install_time(mantis_url, username, password, mantis_project, mantis_id_list, downloads, str_incident_date, gsheet, worksheet_name):
    models = None
    firmwares = None
    rows = {}

    lines = get_lines(mantis_id_list)
    for line in lines:
        m = re.search(r"(\d{5,7}),.*", line)
        if m and m.group(1):
            mantis_id = int(m.group(1))
            diagnostics_path = downloads+'/mantis/'+str(mantis_id)
            print('--- parse Mantis ID: {mantis_id} at {diagnostics_path}'.format(mantis_id=str(mantis_id), diagnostics_path=diagnostics_path))
            if mantis_id in util_globalvar.get_value('g_dont_parse_mantis_id_list') and os.path.isdir(diagnostics_path):
                # the_mantis = mantis(mantis_url, username, password, mantis_project, mantis_id, downloads)
                infection_date = get_infection_date(None, str_incident_date)
                the_qts_install_time = qts_install_time(mantis_id, diagnostics_path, str_incident_date)
            else:
                the_mantis = mantis(mantis_url, username, password, mantis_project, mantis_id, downloads)
                infection_date = get_infection_date(the_mantis, str_incident_date)
                the_qts_install_time = the_mantis.qts_install_time(str_incident_date)

            if the_qts_install_time:
                if 'Model' in the_qts_install_time:
                    model_set = set([the_qts_install_time['Model']])
                    if models is None:
                        models = model_set
                    else:
                        models = models.union(model_set)

                    if mantis_id not in rows:
                        rows[mantis_id] = [str(mantis_id), the_qts_install_time['Model'], None, None]
                    else:
                        rows[mantis_id][1] = the_qts_install_time['Model']
                if 'Firmware' in the_qts_install_time:
                    firmware_set = set([the_qts_install_time['Firmware']])
                    if firmwares is None:
                        firmwares = firmware_set
                    else:
                        firmwares = firmwares.union(firmware_set)
                    if mantis_id not in rows:
                        rows[mantis_id] = [str(mantis_id), None, the_qts_install_time['Firmware'][9:], None]
                    else:
                        rows[mantis_id][2] = the_qts_install_time['Firmware'][9:]
                if mantis_id not in rows:
                    rows[mantis_id] = [str(mantis_id), infection_date, None, None]
                else:
                    rows[mantis_id][3] = 'infection-date [' + infection_date + ']'
                if 'EventLogsLines' in the_qts_install_time:
                    rows[mantis_id][3] += ',' + the_qts_install_time['EventLogsLines']
    
    print('### Summarize {mantis_id_list} data'.format(mantis_id_list=mantis_id_list))
    print('   -- Models')
    for model in models:
        print('      - ' + model)
    print('   -- Firmware')
    for firmware in firmwares:
        print('      - ' + firmware)

    for id in rows:
        gsheet.update_row(worksheet_name, id, rows[id])

def summarize_raid_metadata(mantis_url, username, password, mantis_project, mantis_id_list, downloads, str_incident_date, gsheet, worksheet_name):
    creation_time = None
    rows = {}

    lines = get_lines(mantis_id_list)
    for line in lines:
        m = re.search(r"(\d{5,7}),.*", line)
        if m and m.group(1):
            mantis_id = int(m.group(1))
            diagnostics_path = downloads+'/mantis/'+str(mantis_id)
            print('--- parse Mantis ID: {mantis_id}'.format(mantis_id=str(mantis_id)))
            if mantis_id in util_globalvar.get_value('g_dont_parse_mantis_id_list') and os.path.isdir(diagnostics_path):
                the_raid_metadata = raid_metadata(mantis_id, diagnostics_path, str_incident_date)
            else:
                the_mantis = mantis(mantis_url, username, password, mantis_project, mantis_id, downloads)
                the_raid_metadata = the_mantis.raid_metadata(str_incident_date)

            if the_raid_metadata:
                if 'Creation Time' in the_raid_metadata:
                    creation_time_set = set([the_raid_metadata['Creation Time']])
                    if creation_time is None:
                        creation_time = creation_time_set
                    else:
                        creation_time = creation_time.union(creation_time_set)

                    if mantis_id not in rows:
                        rows[mantis_id] = [str(mantis_id), None, None, None, 'raid created at ' + the_raid_metadata['Creation Time']]
                    else:
                        rows[mantis_id][4] = 'raid created at ' + the_raid_metadata['Creation Time']
    print('### Summarize {mantis_id_list} data'.format(mantis_id_list=mantis_id_list))
    print('   -- Creation Times')
    for item in creation_time:
        print('      - ' + item)

    for id in rows:
        gsheet.update_row(worksheet_name, id, rows[id])

def summarize_qpkg_install_time(mantis_url, username, password, mantis_project, mantis_id_list, downloads, str_incident_date, gsheet, worksheet_name):
    all_exists = None
    appear_once = None
    qpkg_name_2_versions = {}

    lines = get_lines(mantis_id_list)
    for line in lines:
        m = re.search(r"(\d{5,7}),.*", line)
        if m and m.group(1):
            mantis_id = int(m.group(1))
            diagnostics_path = downloads+'/mantis/'+str(mantis_id)
            print('--- parse Mantis ID: {mantis_id}'.format(mantis_id=mantis_id))
            if mantis_id in util_globalvar.get_value('g_dont_parse_mantis_id_list') and os.path.isdir(diagnostics_path):
                from .diagnostics import open_conf
                sections = open_conf(diagnostics_path).sections()
                the_qpkg_conf_update_info = qpkg_conf_update_info(diagnostics_path)
                qpkg_name_2_versions = qpkg_install_time(mantis_id, diagnostics_path, str_incident_date, qpkg_name_2_versions, the_qpkg_conf_update_info)
            else:
                the_mantis = mantis(mantis_url, username, password, mantis_project, mantis_id, downloads)
                sections = the_mantis.qpkg_sections()
                the_qpkg_conf_update_info = the_mantis.qpkg_conf_update_info()
                qpkg_name_2_versions = the_mantis.qpkg_install_time(str_incident_date, qpkg_name_2_versions, the_qpkg_conf_update_info)

            if sections:
                qpkgs = set(sections)
                if all_exists is None:
                    all_exists = qpkgs
                else:
                    all_exists = all_exists.intersection(qpkgs)

                if appear_once is None:
                    appear_once = qpkgs
                else:
                    appear_once = appear_once.union(qpkgs)
    print('### Summarize {mantis_id_list} data'.format(mantis_id_list=mantis_id_list))
    print('   -- All existing QPKGs')
    idx_base = 4
    idx = idx_base
    rows = {}
    for qpkg_name in all_exists:
        idx += 1
        print('      - ' + qpkg_name)
        if qpkg_name in qpkg_name_2_versions:
            for item in qpkg_name_2_versions[qpkg_name]:
                print('        - ' + item)
                id = int(item[2:7])
                if id not in rows:
                    rows[id] = [None] * (len(appear_once)+(idx_base+1))
                    rows[id][0] = item[2:7]
                rows[id][idx] = item[9:]
    print('   -- Appear at least once')
    for qpkg_name in appear_once:
        if qpkg_name not in all_exists:
            idx += 1
            print('      - ' + qpkg_name)
            if qpkg_name in qpkg_name_2_versions:
                for item in qpkg_name_2_versions[qpkg_name]:
                    print('        - ' + item)
                    id = int(item[2:7])
                    if id not in rows:
                        rows[id] = [None] * (len(appear_once)+4)
                        rows[id][0] = item[2:7]
                    rows[id][idx] = item[9:]
    for id in rows:
        gsheet.update_row(worksheet_name, id, rows[id])
