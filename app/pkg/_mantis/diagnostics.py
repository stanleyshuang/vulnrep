#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  mantisanalysis 1.0
# Date:     2021-11-27
#
import configparser
import json
import re

from datetime import datetime

from pkg._util.util_datetime import pick_30_days_before
from pkg._util.util_file import get_sub_folder_list, get_name_list_of_files
from pkg._util.util_text_file import get_lines_b



class search_v5_issues():
    sec2disply_name = {
        'Cinema28': 'Cinema28', # TBD
        'container-station': 'Container Station',
        'helpdesk': 'Helpdesk',
        'HybridBackup': 'Hybrid Backup Sync', # TBD
        'QDMS': 'Media Streaming Add-On',
        'MultimediaConsole': 'Multimedia Console',
        'MusicStation': 'Music Station',
        'NVRStorageExpansion': 'NVR Storage Expansion', # TBD
        'PhotoStation': 'Photo Station',
        'ProxyServer': 'Proxy Server', # TBD
        'qumagie': 'QuMagie',
        'QUSBCam2': 'QUSBCam2', # TBD
        'QVPN': 'QVPN Service', # TBD
        'QVR': 'QVR', # TBD
        'QVRProAppliance': 'QVR Pro Appliance', # TBD
        'RoonServer': 'Roon Server', # TBD
        'SaltStack': 'SaltStack', # TBD
        'StorageExpansion': 'StorageExpansion', # TBD
        'SurveillanceStation': 'Surveillance Station',
        'VideoStationPro': 'Video Station',
    }
    sec_cache = set()
    def __init__(self, gsheet_v):
        self.gsheet_v = gsheet_v
        self.v5_list = gsheet_v.dump_v5()
        self.display_names = set()
        for item in self.v5_list:
            self.display_names.add(item[0])

    def five_digit_match(self, target, remedy):
        m = re.search(r'(\d{1,3})\.(\d{1,2})\.(\d{1,2})\.(\d{1,2})\.(\d{1,6})', target)
        if m and m.group(1) and m.group(2) and m.group(3) and m.group(4) and m.group(5):
            t1 = m.group(1)
            t2 = m.group(2)
            t3 = m.group(3)
            t4 = m.group(4)
            t5 = m.group(5)

            m = re.search(r'(\d{1,3})\.(\d{1,2})\.(\d{1,2})\.(\d{1,2})\.(\d{1,6})', remedy)
            if m and m.group(1) and m.group(2) and m.group(3) and m.group(4) and m.group(5):
                r1 = m.group(1)
                r2 = m.group(2)
                r3 = m.group(3)
                r4 = m.group(4)
                r5 = m.group(5)

                if t1==r1 and t2==r2 and t3==r3 and t4==r4 and int(t5)<int(t5):
                    return True
        return False

    def four_digit_match(self, target, remedy):
        m = re.search(r'(\d{1,3})\.(\d{1,2})\.(\d{1,2})\.(\d{1,6})', target)
        if m and m.group(1) and m.group(2) and m.group(3) and m.group(4):
            t1 = m.group(1)
            t2 = m.group(2)
            t3 = m.group(3)
            t4 = m.group(4)

            m = re.search(r'(\d{1,3})\.(\d{1,2})\.(\d{1,2})\.(\d{1,6})', remedy)
            if m and m.group(1) and m.group(2) and m.group(3) and m.group(4):
                r1 = m.group(1)
                r2 = m.group(2)
                r3 = m.group(3)
                r4 = m.group(4)

                if t1==r1 and t2==r2 and t3==r3 and int(t4)<int(t4):
                    return True
        return False

    def three_digit_match(self, target, remedy):
        m = re.search(r'(\d{1,3})\.(\d{1,2})\.(\d{1,6})', target)
        if m and m.group(1) and m.group(2) and m.group(3):
            t1 = m.group(1)
            t2 = m.group(2)
            t3 = m.group(3)

            m = re.search(r'(\d{1,3})\.(\d{1,2})\.(\d{1,6})', remedy)
            if m and m.group(1) and m.group(2) and m.group(3):
                r1 = m.group(1)
                r2 = m.group(2)
                r3 = m.group(3)

                if t1==r1 and t2==r2 and int(t3)<int(r3):
                    return True
        return False

    def search(self, section, display_name, version):
        product_lists = []
        if section in search_v5_issues.sec2disply_name:
            for item in self.v5_list:
                if item[0]=='Surveillance Station' and display_name==item[0]:
                    if self.five_digit_match(version, item[1]):
                        product_lists.append(item)
                elif item[0]=='Media Streaming Add-On' and display_name==item[0]:
                    if self.four_digit_match(version, item[1]):
                        product_lists.append(item)
                elif display_name==item[0]:
                    if self.three_digit_match(version, item[1]):
                        product_lists.append(item)
        else:
            if section not in search_v5_issues.sec_cache:
                if display_name in self.display_names:
                    print('??? section: '+section+ ' could be wrong..., display_name: '+display_name)
                    search_v5_issues.sec_cache.add(section)
        return product_lists

def index_containing_substring(the_list, the_string):
    for i, s in enumerate(the_list):
        if s in the_string:
            return i
    return -1

def open_conf(diagnostics_path, conf_path='/etc/config/qpkg.conf'):
    subfolders = get_sub_folder_list(diagnostics_path)
    if subfolders and len(subfolders)>0:
        root = subfolders[0]
        conf = configparser.ConfigParser(strict=False)
        try:
            conf.read(diagnostics_path+'/'+root+conf_path)
        except configparser.MissingSectionHeaderError as e:
            print('!!! Exception MissingSectionHeaderError: '+str(e))
        return conf
    return None

def qpkg_conf_update_info(diagnostics_path):
    qpkg_conf_update_info = {}
    the_qpkg_conf = open_conf(diagnostics_path, conf_path='/etc/config/qpkg.conf')
    if the_qpkg_conf:
        sections = the_qpkg_conf.sections()
        for qpkg in sections:
            if qpkg not in qpkg_conf_update_info:
                qpkg_conf_update_info[qpkg] = {}
            if 'Display_Name' in the_qpkg_conf[qpkg]:
                qpkg_conf_update_info[qpkg]['Display_Name'] = the_qpkg_conf[qpkg]['Display_Name']
            if 'Version' in the_qpkg_conf[qpkg]:
                qpkg_conf_update_info[qpkg]['Version'] = the_qpkg_conf[qpkg]['Version']
            if 'Build' in the_qpkg_conf[qpkg]:
                qpkg_conf_update_info[qpkg]['Build'] = the_qpkg_conf[qpkg]['Build']
            if 'Enable' in the_qpkg_conf[qpkg]:
                qpkg_conf_update_info[qpkg]['Enable'] = the_qpkg_conf[qpkg]['Enable']
            if 'Date' in the_qpkg_conf[qpkg]:
                qpkg_conf_update_info[qpkg]['Date'] = the_qpkg_conf[qpkg]['Date']
    return qpkg_conf_update_info

def lines_in_index_pages(diagnostics_path):
    subfolders = get_sub_folder_list(diagnostics_path)
    if subfolders and len(subfolders)>0:
        root = subfolders[0]
        pages = get_name_list_of_files(diagnostics_path+'/'+root)
        if pages and len(pages)>0:
            index_page = pages[0]
            for page in pages:
                if page and page[0]!= '.':
                    index_page = page
                    ### open dianostics logs
                    diagnostics = diagnostics_path+'/'+root+'/'+index_page
                    lines = get_lines_b(diagnostics)
                    return lines
    return None

def lines_in_kernel_logs(diagnostics_path):
    subfolders = get_sub_folder_list(diagnostics_path)
    if subfolders and len(subfolders)>0:
        root = subfolders[0]
        subfolders = get_sub_folder_list(diagnostics_path+'/'+root)
        if 'tmp' in subfolders:
            pages = get_name_list_of_files(diagnostics_path+'/'+root+'/tmp')
            if pages and len(pages)>0 and 'klogd_dump.log' in pages:
                kernel_logs = diagnostics_path+'/'+root+'/tmp/klogd_dump.log'
                lines = get_lines_b(kernel_logs)
                return lines
    return None

def qts_install_time_core(mantis_id, config, eventLines, kernelLines, incident_date):
    print('incident date: {incident_date}'.format(incident_date=incident_date.strftime('%Y-%m-%d')))
    system_events = []
    kernel_events = []
    event_log_begin = 0
    connection_log_begin = 0
    i = 0

    ### Event Logs
    for line in eventLines:
        if i<20 and any(substring in line for substring in ['Model:', 'Firmware:', 'Date:']):
            if line.find('Model:')>=0:
                config['Model'] = line[7:len(line)-1]
                print(config['Model'])
            elif line.find('Firmware:')>=0:
                config['Firmware'] = '[#' + str(mantis_id) + '] [' + config['Date'] + '] ' + line[10:len(line)-1]
                print(config['Firmware'])
            elif line.find('Date:')>=0:
                config['Date'] = line[6:len(line)-1]
                print(config['Date'])

        ### collecting logs into system_events
        # if line.find('[Firmware Update] Started downloading firmware')>=0:
        if line.find('[Firmware Update]')>=0:
            system_events.append(line)

        i += 1
        if line.find('============= [ EVENT LOG ]')>=0:
            event_log_begin = i
        if line.find('============= [ CONNECTION LOG ]')>=0:
            connection_log_begin = i
            if connection_log_begin - event_log_begin < 30:
                config['EventLogsLines'] = 'event-log-line# [' + str(connection_log_begin-event_log_begin) + ']'


    system_event_line_ptns = [
        r"\d{2,7},  \d{1,5},(\d{4}-\d{2}-\d{2}),\d{2}:\d{2}:\d{2},.*?,\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3},.*?,\[Firmware Update\] Started downloading firmware (\d{1}.\d{1}.\d{1}.\d{4} Build \d{8})\.,",
        r"\d{2,7},  \d{1,5},(\d{4}-\d{2}-\d{2}),\d{2}:\d{2}:\d{2},.*?,\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3},.*?,\[Firmware Update\] Start downloading firmware (\d{1}.\d{1}.\d{1}.\d{4} Build \d{8})\.,",
        r"\d{2,7},  \d{1,5},(\d{4}-\d{2}-\d{2}),\d{2}:\d{2}:\d{2},.*?,\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3},.*?,\[Firmware Update\] Updated system from version \d{1}.\d{1}.\d{1}.\d{4}\(\d{8}\) to (\d{1}.\d{1}.\d{1}.\d{4}\(\d{8}\))\.,",
        r"\d{2,7},  \d{1,5},(\d{4}-\d{2}-\d{2}),\d{2}:\d{2}:\d{2},.*?,\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3},.*?,\[Firmware Update\] System updated successfully from \d{1}\.\d{1}\.\d{1}\(\d{8}\) to (\d{1}\.\d{1}\.\d{1}\(\d{8}\))\.,",
    ]
    qts_install_date = None
    for event in reversed(system_events):
        b_match = False
        for line_ptn in system_event_line_ptns:
            m = re.search(line_ptn, event)
            if m and m.group(1) and m.group(2):
                the_date = datetime.strptime(m.group(1), '%Y-%m-%d')
                qts_version = '[#' + str(mantis_id) + '] [' + m.group(1) + '] QTS ' + m.group(2)
                print('event: {qts_version}'.format(qts_version=qts_version))
                if the_date<incident_date:
                    config['Firmware'] = qts_version
                    qts_install_date = the_date
                    b_match = True
                    print('update {firmware}'.format(firmware=qts_version))
                    break
        if b_match:
            break

    ### Kernel Logs
    if kernelLines:
        for line in kernelLines:
            ### collecting logs into kernel_events
            if line.find(') boot finished.')>=0:
                kernel_events.append(line)


    kernel_event_line_ptns = [
        r" ====== (\d{4}-\d{2}-\d{2}) \d{2}:\d{2}:\d{2} .*? \((\d{1}\.\d{1}\.\d{1}\.\d{4}-\d{8})\) boot finished\.",
    ]
    for event in reversed(kernel_events):
        b_match = False
        for line_ptn in kernel_event_line_ptns:
            m = re.search(line_ptn, event)
            if m and m.group(1) and m.group(2):
                the_date = datetime.strptime(m.group(1), '%Y-%m-%d')
                qts_version = '[#' + str(mantis_id) + '] [' + m.group(1) + '] QTS ' + m.group(2)
                print('kernel: {qts_version}'.format(qts_version=qts_version))
                if the_date<incident_date and (qts_install_date is None or qts_install_date<the_date):
                    config['Firmware'] = qts_version
                    qts_install_date = the_date
                    b_match = True
                    print('update {firmware}'.format(firmware=qts_version))
                    break
        if b_match:
            break
    return config

def qts_install_time(mantis_id, diagnostics_path, str_incident_date):
    now = datetime.now()
    config = {'Date': now.strftime('%Y-%m-%d')}
    incident_date = datetime.strptime(str_incident_date, '%Y-%m-%d')
    eventLines = lines_in_index_pages(diagnostics_path)
    kernelLines = lines_in_kernel_logs(diagnostics_path)
    config = qts_install_time_core(mantis_id, config, eventLines, kernelLines, incident_date)
            
    if len(config)>1:
        return config
    else:
        return None

def raid_metadata(mantis_id, diagnostics_path, str_incident_date):
    config = {}
    lines = lines_in_index_pages(diagnostics_path)
    if lines:
        b_md_superblock = False
        for line in lines:
            if line.find('Welcome to MD superblock checker')>=0:
                b_md_superblock = True
                i = 0
            if b_md_superblock and i<20 and any(substring in line for substring in ['Creation Time:']):
                if line.find('Creation Time:')>=0:
                    config['Creation Time'] = line[14:len(line)-1].strip()
                    b_md_superblock = False
                    print(config['Creation Time'])
                i += 1
    if len(config)>0:
        return config
    else:
        return None

def linefilter(mantis_id, diagnostics_path, gsheet_v):
    lines = lines_in_index_pages(diagnostics_path)
    if lines:
        for line in lines:
            if line.find('[Malware Remover]')>=0:
                if line.find('Started scanning.,')>=0:
                    continue
                elif line.find('Scan completed.,')>=0:
                    continue
                else:
                    print(line)


def qpkg_install_time(mantis_id, diagnostics_path, str_incident_date, qpkg_name_2_versions, qpkg_list, gsheet_v):
    v5_issues = search_v5_issues(gsheet_v)
    keywords = []
    sections = []
    ### prepare the index of the sections and display names 
    nicknames = {
        'VideoStationPro': ['Video Station', 'VideoStation HD (Local Display)'],
        'PhotoStation': ['Photo Station'],
        'MusicStation': ['Music Station'],
        'DownloadStation': ['Download Station'],
        'QsyncServer': ['Qsync Central'],
        'QDMS': ['Media Streaming Add-on', 'Media Streaming add-on'],
        'MalwareRemover': ['Malware Remover'],
        'helpdesk': ['Helpdesk'],
        'QuMagieCore': ['QuMagieCore', 'QuMagie Core','QNAP AI Core'],
        'qumagie': ['QuMagie'],
        'MediaSignPlayer': ['CAYIN MediaSign Player'],
        'SSDLaboratory': ['SSD Profiling Tool'],
        'LicenseCenter': ['License Center'],
        'SecurityCounselor': ['Security Counselor'],
        'MultimediaConsole': ['Multimedia Console'],
        'container-station': ['Container Station'],
        'QuFTP': ['QuFTP Service'],
        'NVIDIA_GPU_DRV': ['NVIDIA GPU Driver'],
        'Qbutton': ['QButton'],
        'Driveanalyzer': ['DA Drive Analyzer'],
        'EmbyServer': ['Emby Server'],
        'NotesStation3': ['Notes Station 3'],
        'CloudLink': ['myQNAPcloud Link'],
        'NotificationCenter': ['Notification Center'],
        'CacheMount': ['HybridMount'],
        'Qcenter-Agent': ['Q\'center Agent'],
        'HybridBackup': ['Hybrid Backup Sync'],
        'MCAFEE_QNAP': ['McAfee Antivirus'],
        'qmail': ['QmailAgent'],
        'owncloudv10': ['owncloudX'],
        'Qcenter': ['Q\'center'],
        'ResourceMonitor': ['Resource Monitor'],
        'TextEditor': ['Text Editor'],
        'netmgr': ['Network & Virtual Switch'],
        'QcloudSSLCertificate': ['QTS SSL Certificate'],
        'PlexMediaServer': ['Plex Media Server'],
        'browser-station': ['Browser Station'],
        'SDDPd': ['SDDP'],
        'Qboost': ['Qboost'],
        'QVPN': ['QVPN Service'],
        'HD_Station': ['HybridDesk Station'],
        'Qsirch': ['Qsirch'],
        'QuLog': ['QuLog'],
    }
    if qpkg_list:
        for section in qpkg_list:
            keywords.append(section)
            sections.append(section)
            if 'Display_Name' in qpkg_list:
                keywords.append(qpkg_list['Display_Name'])
                sections.append(section)
            else:
                print('??? '+section+ ': No Display Name information..')
            if section in nicknames:
                keywords.extend(nicknames[section])
                sections.extend([section]*len(nicknames[section]))
        print('QPKG keywords: '+str(keywords))

    incident_date = datetime.strptime(str_incident_date, '%Y-%m-%d')

    system_event_line_ptns = [
        r"\d{2,7},  \d{1,5},(\d{4}-\d{2}-\d{2}),\d{2}:\d{2}:\d{2},.*?,\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3},.*?,\[App Center\] Installed (.*?) in",
        r"\d{2,7},  \d{1,5},(\d{4}-\d{2}-\d{2}),\d{2}:\d{2}:\d{2},.*?,\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3},.*?,\[App Center\] (.*?) updated\.,",
        r"\d{2,7},  \d{1,5},(\d{4}-\d{2}-\d{2}),\d{2}:\d{2}:\d{2},.*?,\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3},.*?,\[App Center\] (.*?) installation succeeded\.,",
    ]

    system_events = {}
    lines = lines_in_index_pages(diagnostics_path)
    if lines:
        for line in lines:
            if line.find('[App Center]')>=0:
                idx = index_containing_substring(keywords, line)
                ### collecting logs into system_events
                if idx>=0:
                    qpkg_name = sections[idx] # qpkg_name 是 qpkg.conf 中的 section name
                    for ptn in system_event_line_ptns:
                        m = re.search(ptn, line)
                        if m and m.group(1) and m.group(2): 
                            the_time = m.group(1)
                            qpkg_version = '[' + m.group(1) + '] ' + m.group(2)

                            if qpkg_name in nicknames:
                                remedies = v5_issues.search(qpkg_name, nicknames[qpkg_name][0], m.group(2))
                                if remedies and len(remedies)>0:
                                    qpkg_version += ' [!!!] Remedies: ' + str(remedies)
                            else:
                                print('??? {qpkg_name} is not in nicknames'.format(qpkg_name=qpkg_name))

                            if qpkg_name not in system_events:
                                system_events[qpkg_name] = []
                            system_events[qpkg_name].append(qpkg_version)
                            break
                        else:
                            continue
                else:
                    if line.find('Unable to obtain the latest app update information online.')>=0:
                        pass
                    elif line.find('Updates are temporarily unavailable. Please try again later.')>=0:
                        pass
                    elif line.find('Stopped Transmission.')>=0:
                        pass
                    elif line.find('Started Transmission.')>=0:
                        pass
                    else:
                        print('??? [App Center] unrecognized QPKG: '+line)
        ### the data of qpkg.conf is in qpkg_list
        if qpkg_list:
            for qpkg_name in qpkg_list:
                display_name = 'n/a'
                version = ''
                build = ''
                enable = ''
                if 'Display_Name' in qpkg_list[qpkg_name]:
                    display_name = qpkg_list[qpkg_name]['Display_Name']
                if 'Version' in qpkg_list[qpkg_name]:
                    version = qpkg_list[qpkg_name]['Version']
                if 'Build' in qpkg_list[qpkg_name]:
                    build = qpkg_list[qpkg_name]['Build']
                if 'Enable' in qpkg_list[qpkg_name]:
                    enable = qpkg_list[qpkg_name]['Enable']
                if 'Date' in qpkg_list[qpkg_name]:
                    lstest_update = datetime.strptime(qpkg_list[qpkg_name]['Date'], '%Y-%m-%d')
                    qpkg_version = '[#' + str(mantis_id) + '] [' + qpkg_list[qpkg_name]['Date'] + '] ' + display_name + ' ' + version + ' ' + build
                    if enable=='FALSE':
                        qpkg_version += '[x]'

                    remedies = v5_issues.search(qpkg_name, display_name, version)
                    if remedies and len(remedies)>0:
                        qpkg_version += ' [!!!] Remedies: ' + str(remedies)

                    print('{qpkg_name} : {qpkg_version}'.format(qpkg_name=qpkg_name, qpkg_version=qpkg_version))
                    if lstest_update<incident_date:
                        if qpkg_name not in qpkg_name_2_versions:
                            qpkg_name_2_versions[qpkg_name] = []
                        qpkg_name_2_versions[qpkg_name].append(qpkg_version)
                    else:
                        b_event_found = False
                        if qpkg_name in system_events:
                            for event in reversed(system_events[qpkg_name]):
                                m = re.search(r"\[(\d{4}-\d{2}-\d{2})\]", event)
                                if m and m.group(1):
                                    the_date = datetime.strptime(m.group(1), '%Y-%m-%d')
                                    qpkg_version = '[#' + str(mantis_id) + '] ' + event
                                    if enable=='FALSE':
                                        qpkg_version += '[x]'
                                    print('{qpkg_name} : {qpkg_version}'.format(qpkg_name=qpkg_name, qpkg_version=qpkg_version))
                                    if the_date<incident_date:
                                        if qpkg_name not in qpkg_name_2_versions:
                                            qpkg_name_2_versions[qpkg_name] = []
                                        qpkg_name_2_versions[qpkg_name].append(qpkg_version)
                                        b_event_found = True
                                        break
                        if not b_event_found:
                            if qpkg_name not in qpkg_name_2_versions:
                                qpkg_name_2_versions[qpkg_name] = []
                            qpkg_name_2_versions[qpkg_name].append(qpkg_version + '[cfg]')

    return qpkg_name_2_versions

def system_log_time_filter(events):
    output = []
    now = datetime.now()
    a_month_ago = pick_30_days_before(now)
    b_printed = False
    for event in events:
        m = re.search(r"\d{3,7},  \d{1,5},(\d{4}-\d{2}-\d{2}),\d{2}:\d{2}:\d{2},", event)
        if m and m.group(1):
            str_the_date = m.group(1)
            the_date = datetime.strptime(str_the_date, '%Y-%m-%d')
            if the_date>=a_month_ago:
                output.append(event)
                b_printed = True
    if not b_printed and len(events)>0:
        output.append(event[-1])
    return output


def parse_infection_date(line):
    m = re.search(r"[Ii]nfection[ -_][Dd]ate[:]*[ ]*(\d{0,4})[/-](\d{1,2})[/-](\d{1,2})", line)
    if m and m.group(1) and m.group(2) and m.group(3):
        str_the_date = m.group(1) + '-' + m.group(2) + '-' + m.group(3)
        return datetime.strptime(str_the_date, '%Y-%m-%d')
    return None

def get_infection_date(mantis, first_infection_date=datetime.strftime(datetime.now(),'%Y-%m-%d')):
    if mantis and 'additional_information' in mantis.issue:
        content = mantis.issue['additional_information']
        if content is None:
            return first_infection_date
        lines = content.lower().splitlines()
        for line in lines:
            if line.find('infection')>=0:
                infection_date = parse_infection_date(line)
                if infection_date:
                    return datetime.strftime(infection_date,'%Y-%m-%d')
    return first_infection_date

def smb_conf_update_info(diagnostics_path):
    smb_conf_update_info = {}
    the_smb_conf = open_conf(diagnostics_path, conf_path='/etc/config/smb.conf')
    if the_smb_conf:
        sections = the_smb_conf.sections()
        for sec in sections:
            if sec not in smb_conf_update_info:
                smb_conf_update_info[sec] = {}
            if 'public' in the_smb_conf[sec]:
                smb_conf_update_info[sec]['public'] = the_smb_conf[sec]['public']
    return smb_conf_update_info

