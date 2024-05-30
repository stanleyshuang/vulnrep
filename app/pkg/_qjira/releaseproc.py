#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2021-07-25
#
import json
from pkg._util.util_datetime import duration_days
from . import i_issue, get_issuetype
from .description import extract_model

class i_releaseproc(i_issue):
    '''
    Jira release process
    '''
    def __init__(self, jira, issue, debug_obj):
        super(i_releaseproc, self).__init__(jira, issue, debug_obj)
        self.end_states = []

    def trace_dependency(self):
        if self.b_dependency_traced:
            return
        self.b_dependency_traced = True
        self.dependent_counts = 0
        self.dependent_issues = []

class fw_release_process(i_releaseproc):
    '''
    Jira fw_release_process
    '''
    def __init__(self, jira, issue, debug_obj):
        super(fw_release_process, self).__init__(jira, issue, debug_obj)
        if get_issuetype(self.issue)!='FW Release Process' and get_issuetype(self.issue)!='Product Testing Task':
            raise Exception("Jira issuetype mismatch!!")
        if self.get_status_name() in ['done']:
            self.b_resolved = True
        self.end_states = ['Done', 'Release test fail and closed', 'abort']

    def at_completed_states(self):
        return self.get_status_name() in ['done', 'abort']

    def at_failed_states(self):
        return self.get_status_name() in ['release test fail and closed']
    
    def trace_dependency(self):
        if self.b_dependency_traced:
            return
        self.b_dependency_traced = True
        self.dependent_counts = 0
        self.dependent_issues = []
        self.search_is_cloned_by()
        for is_cloned_by_issue in self.is_cloned_by_issues:
            if get_issuetype(is_cloned_by_issue) == 'FW Release Process':
                the_fwrelease = fw_release_process(self.jira, is_cloned_by_issue, self.debug_obj)
                self.dependent_counts += 1
                self.dependent_issues.append(the_fwrelease)
        self.search_causes()
        for causes_issue in self.causes_issues:
            if get_issuetype(causes_issue) == 'FW Delivery Process':
                the_fwdelivery = fw_delivery_process(self.jira, causes_issue, self.debug_obj)
                self.dependent_counts += 1
                self.dependent_issues.append(the_fwdelivery)

    def get_gsheet_raw(self):
        from pkg._qjira.description import parse_fw_release_process
        created_time, str_created_time = self.get_created_n_str()
        raw = {}
        author, changed, status = self.get_auther_and_created_in_changlog('status', self.end_states)
        if self.at_completed_states():
            changed_time, str_changed_time = self.get_time_n_str(changed)
            raw['created'] = str_created_time
            raw['key'] = self.issue.key
            if self.get_status_name() in ['done']:
                raw['name'] = author
                raw['completed'] = str_changed_time
                raw['duration'] = duration_days(created_time, changed_time)
            raw['status'] = self.get_status_name()
            raw['summary'] = self.issue.fields.summary
            raw['applied_model'] = ''
            raw['build_number'] = self.issue.raw['fields']["customfield_11807"]
            raw['product'], raw['platform'], raw['version_n_build'], raw['version_begin'] = parse_fw_release_process(self.issue.key, 
                                                                                               self.issue.fields.summary, 
                                                                                               self.issue.raw['fields']["customfield_11807"])
        elif self.at_failed_states():
            changed_time, str_changed_time = self.get_time_n_str(changed)
            raw['created'] = str_created_time
            raw['key'] = self.issue.key
            '''
            raw['name'] = author
            raw['completed'] = str_changed_time
            raw['duration'] = duration_days(created_time, changed_time)
            '''
            raw['status'] = self.get_status_name()
            raw['summary'] = self.issue.fields.summary
            raw['applied_model'] = ''
            raw['build_number'] = self.issue.raw['fields']["customfield_11807"]
            raw['product'], raw['platform'], raw['version_n_build'], raw['version_begin'] = parse_fw_release_process(self.issue.key, 
                                                                                               self.issue.fields.summary, 
                                                                                               self.issue.raw['fields']["customfield_11807"])
        else:
            raw['created'] = str_created_time
            raw['key'] = self.issue.key
            raw['status'] = self.get_status_name()
            raw['summary'] = self.issue.fields.summary
            raw['applied_model'] = ''
            raw['build_number'] = self.issue.raw['fields']["customfield_11807"]
            raw['product'], raw['platform'], raw['version_n_build'], raw['version_begin'] = parse_fw_release_process(self.issue.key, 
                                                                                               self.issue.fields.summary, 
                                                                                               self.issue.raw['fields']["customfield_11807"])
        if self.b_resolved:
            raw['done'] = 'Yes'
        else:
            raw['done'] = 'No'
        # self.debuglog_v(json.dumps(raw, indent=4))
        return raw

    def run(self, root_issue, parent_issue, data, downloads, b_update=False):
        self.debuglog_i('  [FW RELEASE-{key}] Run'.format(key=self.issue.key))
        if self.issue.key == 'CMNBSIMM-732':
            # EOL process
            self.debuglog_i('  [FW RELEASE-{key}] EOL'.format(key=self.issue.key))
        self.trace_dependency()
        '''
        b_add_component_vulnerability_report = False
        if b_update and self.does_component_exit('vulnerability_report'):
            b_add_component_vulnerability_report = True
        '''
        raws = []
        fw_delivery_process_count = 0
        b_resolved = False
        for issue in self.dependent_issues:
            if get_issuetype(issue.issue) == 'FW Delivery Process':
                raw = issue.run(parent_issue, self, data, downloads, b_update)
                raws.append(raw)
                fw_delivery_process_count += 1
                the_fwdelivery = issue
                if the_fwdelivery.b_resolved:
                    b_resolved = True
                '''
                if b_add_component_vulnerability_report:
                    the_fwdelivery.add_component('vulnerability_report')
                '''
        # 如果找不到已解 FW Delivery Process，回頭看看有沒有其他的 FW Release Process
        if not b_resolved:
            for issue in self.dependent_issues:
                if get_issuetype(issue.issue) == 'FW Release Process':
                    children = issue.run(root_issue, parent_issue, data, downloads, b_update)
                    raws.extend(children)
                    # fw_delivery_process_count += 1
                    the_fwrelease = issue
                    '''
                    if b_add_component_vulnerability_report:
                        the_fwrelease.add_component('vulnerability_report')
                    '''
                    if the_fwrelease.b_resolved:
                        b_resolved = True
                        break

        if self.at_completed_states():
            self.b_resolved = b_resolved
        elif self.at_failed_states():
            self.b_resolved = False
        else:
            self.b_resolved = False

        if not self.b_resolved and not self.at_failed_states() and fw_delivery_process_count==0:
            if self.get_status_name() in ['ready for testing']:
                owner, str_long_time, status = self.get_auther_and_created_in_changlog('status', ['Ready for Testing'])
                the_time, str_time = self.get_time_n_str(str_long_time)
                model, product, ver=extract_model(parent_issue.issue.fields.summary)
                self.debuglog_r('     ┌> [APP Release-{key}] - [{product}] in Ready for Testing (no FW DELIVERY PROCESS) - [Bug-{parent_key}]'.format(key=self.issue.key, 
                                                                                                                                          parent_key=parent_issue.issue.key,
                                                                                                                                          product=product), since=the_time)
            elif self.get_status_name() in ['fw testing']:
                owner, str_long_time, status = self.get_auther_and_created_in_changlog('status', ['FW testing'])
                the_time, str_time = self.get_time_n_str(str_long_time)
                model, product, ver=extract_model(parent_issue.issue.fields.summary)
                self.debuglog_r('     ┌> [APP Release-{key}] - [{product}] in FW testing (no FW DELIVERY PROCESS) - [Bug-{parent_key}]'.format(key=self.issue.key, 
                                                                                                                                          parent_key=parent_issue.issue.key,
                                                                                                                                          product=product), since=the_time)
            else:
                owner, str_long_time, status = self.get_auther_and_created_in_changlog('status', ['Test completed'])
                if str_long_time:
                    the_time, str_time = self.get_time_n_str(str_long_time)
                    model, product, ver=extract_model(parent_issue.issue.fields.summary)
                    self.debuglog_r('     ┌> [APP Release-{key}] - [{product}] in Test completed (no FW DELIVERY PROCESS) - [Bug-{parent_key}]'.format(key=self.issue.key, 
                                                                                                                                          parent_key=parent_issue.issue.key,
                                                                                                                                          product=product), since=the_time)
                else:
                    the_time, str_time = self.get_created_n_str()
                    model, product, ver=extract_model(parent_issue.issue.fields.summary)
                    self.debuglog_r('     ┌> [APP Release-{key}] - [{product}] in opening (no FW DELIVERY PROCESS PROCESS) - [Bug-{parent_key}]'.format(key=self.issue.key, 
                                                                                                                                          parent_key=parent_issue.issue.key,
                                                                                                                                          product=product), since=the_time)
        '''
        if 'NVRQVRSV' in self.issue.key:
            raw = self.get_gsheet_raw()
            # self.gsheet.fw_del_proc(root_issue.issue, raw)
            raws.append(raw)
        '''
        return raws

    def check(self, root_issue, parent_issue, data, downloads, b_update=False):
        return self.run(root_issue, parent_issue, data, downloads, b_update=b_update)

class fw_delivery_process(i_releaseproc):
    '''
    Jira fw_delivery_process
    '''
    def __init__(self, jira, issue, debug_obj):
        super(fw_delivery_process, self).__init__(jira, issue, debug_obj)
        if get_issuetype(self.issue) != 'FW Delivery Process':
            raise Exception("Jira issuetype mismatch!!")
        if self.get_status_name() in ['close', 'xml testing', 'confirm release time', 'fw publish']:
            self.b_resolved = True
        self.end_states = ['close', 'XML testing', 'Confirm Release Time','FW Publish'] # toString 格式

    def at_completed_states(self):
        return self.get_status_name() in ['close', 'xml testing', 'confirm release time', 'fw publish']

    def get_gsheet_raw(self):
        from pkg._qjira.description import parse_fw_delivery_process
        created_time, str_created_time = self.get_created_n_str()
        raw = {}
        author, changed, status = self.get_auther_and_created_in_changlog('status', self.end_states)
        file_link = self.issue.raw['fields']["customfield_11828"]
        if self.issue.key.find('QVPMANPJ') >= 0:
            file_link = str(self.issue.raw['fields']["customfield_13703"])
        if self.at_completed_states():
            changed_time, str_changed_time = self.get_time_n_str(changed)
            raw['created'] = str_created_time
            raw['key'] = self.issue.key
            raw['name'] = author
            raw['completed'] = str_changed_time
            raw['duration'] = duration_days(created_time, changed_time)
            raw['status'] = self.get_status_name()
            raw['summary'] = self.issue.fields.summary
            raw['applied_model'] = self.issue.raw['fields']["customfield_12701"][0:50] if self.issue.raw['fields']["customfield_12701"] else ''
            raw['build_number'] = self.issue.raw['fields']["customfield_11807"]
            raw['product'], raw['platform'], raw['version_n_build'], raw['version_begin'] = parse_fw_delivery_process(self.issue.key, 
                                                                                                self.issue.raw['fields']["customfield_12701"],
                                                                                                self.issue.raw['fields']["customfield_11807"],
                                                                                                file_link)
        elif self.at_failed_states():
            changed_time, str_changed_time = self.get_time_n_str(changed)
            raw['created'] = str_created_time
            raw['key'] = self.issue.key
            raw['name'] = author
            raw['completed'] = str_changed_time
            raw['duration'] = duration_days(created_time, changed_time)
            raw['status'] = self.get_status_name()
            raw['summary'] = self.issue.fields.summary
            raw['applied_model'] = self.issue.raw['fields']["customfield_12701"][0:50]
            raw['build_number'] = self.issue.raw['fields']["customfield_11807"]
            raw['product'], raw['platform'], raw['version_n_build'], raw['version_begin'] = parse_fw_delivery_process(self.issue.key, 
                                                                                                self.issue.raw['fields']["customfield_12701"],
                                                                                                self.issue.raw['fields']["customfield_11807"],
                                                                                                file_link)
        elif 'customfield_12701' in self.issue.raw['fields'] and self.issue.raw['fields']["customfield_12701"]:
            raw['created'] = str_created_time
            raw['key'] = self.issue.key
            raw['status'] = self.get_status_name()
            raw['summary'] = self.issue.fields.summary
            raw['applied_model'] = self.issue.raw['fields']["customfield_12701"][0:50]
            raw['build_number'] = self.issue.raw['fields']["customfield_11807"]
            raw['product'], raw['platform'], raw['version_n_build'], raw['version_begin'] = parse_fw_delivery_process(self.issue.key, 
                                                                                                self.issue.raw['fields']["customfield_12701"],
                                                                                                self.issue.raw['fields']["customfield_11807"],
                                                                                                file_link)
        else:
            self.debuglog_r('     !! [FW DELIVERY-{key}] field [customfield_12701] (Applied Model) not exist'.format(key=self.issue.key))

        if self.b_resolved:
            raw['done'] = 'Yes'
        else:
            raw['done'] = 'No'
        # self.debuglog_v(json.dumps(raw, indent=4))
        return raw

    def run(self, root_issue, parent_issue, data, downloads, b_update=False):
        from pkg._qjira.description import parse_fw_delivery_process
        self.debuglog_i('  [FW DELIVERY-{key}] Run'.format(key=self.issue.key))
        self.trace_dependency()
        raw = self.get_gsheet_raw()
        file_link = self.issue.raw['fields']["customfield_11828"]
        if self.issue.key.find('QVPMANPJ') >= 0:
            file_link = str(self.issue.raw['fields']["customfield_13703"])
        if self.at_completed_states():
            self.b_resolved = True
            product, platform, ver_n_bld, ver_begin = parse_fw_delivery_process(self.issue.key, 
                                                                     self.issue.raw['fields']["customfield_12701"],
                                                                     self.issue.raw['fields']["customfield_11807"],
                                                                     file_link)
            # resolutiondate_str = self.issue.fields.resolutiondate[:10]
            author, changed, status = self.get_auther_and_created_in_changlog('status', self.end_states)
            changed_time, str_changed_time = self.get_time_n_str(changed)
            resolutiondate_str = str_changed_time[:10]
            self.debuglog_r('     ┌* [FW DELIVERY-{key}] - [{product}][{platform}][{ver_n_bld}][{resolutiondate_str}] CLOSE'.format(key=self.issue.key, product=product, platform=platform, ver_n_bld=ver_n_bld, resolutiondate_str=resolutiondate_str))
        elif self.at_failed_states():
            self.b_resolved = False
            the_time, str_time = self.get_created_n_str()
            model, product, ver=extract_model(parent_issue.issue.fields.summary)
            self.debuglog_r('     ┌> [FW DELIVERY-{key}] - [{product}] failed'.format(key=self.issue.key, product=product), since=the_time)
        else:
            self.b_resolved = False
            the_time, str_time = self.get_created_n_str()
            model, product, ver=extract_model(parent_issue.issue.fields.summary)
            self.debuglog_r('     ┌> [FW DELIVERY-{key}] - [{product}] in opening'.format(key=self.issue.key, product=product), since=the_time)
        # self.gsheet.fw_del_proc(root_issue.issue, raw)
        return raw

    def check(self, root_issue, parent_issue, data, downloads, b_update=False):
        return self.run(root_issue, parent_issue, data, downloads, b_update=b_update)

class app_release_process(i_releaseproc):
    '''
    Jira app_release_process
    '''
    def __init__(self, jira, issue, debug_obj):
        super(app_release_process, self).__init__(jira, issue, debug_obj)
        if get_issuetype(self.issue) != 'App Release Process':
            raise Exception("Jira issuetype mismatch!!")
        if self.get_status_name() in ['done']:
            self.b_resolved = True
        self.end_states = ['Done', 'Release test fail and closed', 'abort']

    def at_completed_states(self):
        if self.issue.key=='CMNBSIMM-214':
            return True
        return self.get_status_name() in ['done', 'abort']

    def at_failed_states(self):
        return self.get_status_name() in ['release test fail and closed']

    def trace_dependency(self):
        if self.b_dependency_traced:
            return
        self.b_dependency_traced = True
        self.dependent_counts = 0
        self.dependent_issues = []
        self.search_causes()
        for causes_issue in self.causes_issues:
            if get_issuetype(causes_issue) == 'Store Publish Process':
                the_storepublish = store_publish_process(self.jira, causes_issue, self.debug_obj)
                self.dependent_counts += 1
                self.dependent_issues.append(the_storepublish)

    def run(self, root_issue, parent_issue, data, downloads, b_update=False):
        self.debuglog_i('  [APP RELEASE-{key}] Run'.format(key=self.issue.key))
        if self.issue.key == 'CMNBSIMM-731':
            # EOL process
            self.debuglog_i('  [APP RELEASE-{key}] EOL'.format(key=self.issue.key))
        self.trace_dependency()
        '''
        b_add_component_vulnerability_report = False
        if b_update and self.does_component_exit('vulnerability_report'):
            b_add_component_vulnerability_report = True
        '''
        raws = []
        b_resolved = False
        store_publish_process_count = 0
        if self.issue.key=='CMNBSIMM-214' or self.issue.key.find('CLDMQC00')>=0:
            ### For Web Site verification
            b_resolved = True
            if parent_issue and parent_issue.issue.fields.resolutiondate:
                resolutiondate_str = parent_issue.issue.fields.resolutiondate[:10]
            else:
                resolutiondate_str = ''
            self.debuglog_r('     ┌* [APP Release-{key}] - [{resolutiondate_str}] WEB'.format(key=self.issue.key, resolutiondate_str=resolutiondate_str))
        else:
            for issue in self.dependent_issues:
                if get_issuetype(issue.issue) == 'Store Publish Process':
                    raw = issue.run(parent_issue, self, data, downloads, b_update)
                    raws.append(raw)
                    store_publish_process_count += 1
                    the_storepublish = issue
                    if the_storepublish.b_resolved:
                        b_resolved = True
                    '''
                    if b_add_component_vulnerability_report:
                        the_storepublish.add_component('vulnerability_report')
                    '''

        if self.at_completed_states():
            self.b_resolved = b_resolved
        elif self.at_failed_states():
            self.b_resolved = False
        else:
            self.b_resolved = False

        if not self.b_resolved and not self.at_failed_states() and store_publish_process_count==0:
            if self.get_status_name() in ['app testing']:
                owner, str_long_time, status = self.get_auther_and_created_in_changlog('status', ['APP Testing'])
                the_time, str_time = self.get_time_n_str(str_long_time)
                model, product, ver=extract_model(parent_issue.issue.fields.summary)
                self.debuglog_r('     ┌> [APP Release-{key}] - [{product}] in APP Tesing (no STORE PUBLISH PROCESS) - [Bug-{parent_key}]'.format(key=self.issue.key, 
                                                                                                                                          parent_key=parent_issue.issue.key,
                                                                                                                                          product=product), since=the_time)
            else:
                owner, str_long_time, status = self.get_auther_and_created_in_changlog('status', ['Test completed'])
                if str_long_time:
                    the_time, str_time = self.get_time_n_str(str_long_time)
                    model, product, ver=extract_model(parent_issue.issue.fields.summary)
                    self.debuglog_r('     ┌> [APP Release-{key}] - [{product}] in Test completed (no STORE PUBLISH PROCESS) - [Bug-{parent_key}]'.format(key=self.issue.key, 
                                                                                                                                          parent_key=parent_issue.issue.key,
                                                                                                                                          product=product), since=the_time)
                else:
                    the_time, str_time = self.get_created_n_str()
                    model, product, ver=extract_model(parent_issue.issue.fields.summary)
                    self.debuglog_r('     ┌> [APP Release-{key}] - [{product}] in opening (no STORE PUBLISH PROCESS) - [Bug-{parent_key}]'.format(key=self.issue.key, 
                                                                                                                                          parent_key=parent_issue.issue.key,
                                                                                                                                          product=product), since=the_time)
        elif not self.b_resolved and self.at_failed_states():
            owner, str_long_time, status = self.get_auther_and_created_in_changlog('status', ['Test completed'])
            the_time, str_time = self.get_time_n_str(str_long_time)
            model, product, ver=extract_model(parent_issue.issue.fields.summary)
            self.debuglog_r('     ┌> [Bug-{parent_key}][{product}] - Release Test Fail and Closed [APP Release-{key}]'.format(key=self.issue.key, 
                                                                                                                                  parent_key=parent_issue.issue.key,
                                                                                                                                  product=product), since=the_time)
        return raws

    def check(self, root_issue, parent_issue, data, downloads, b_update=False):
        return self.run(root_issue, parent_issue, data, downloads, b_update=b_update)

class store_publish_process(i_releaseproc):
    '''
    Jira store_publish_process
    '''
    def __init__(self, jira, issue, debug_obj):
        super(store_publish_process, self).__init__(jira, issue, debug_obj)
        if get_issuetype(self.issue) != 'Store Publish Process':
            raise Exception("Jira issuetype mismatch!!")
        if self.get_status_name() in ['close']: # 'preparing xml'
            self.b_resolved = True
        self.end_states = ['close'] # 'Preparing XML'
 
    def at_completed_states(self):
        return self.get_status_name() in ['close'] # 'preparing xml'

    def get_gsheet_raw(self):
        from pkg._qjira.description import parse_store_publish_process
        created_time, str_created_time = self.get_created_n_str()
        raw = {}
        author, changed, status = self.get_auther_and_created_in_changlog('status', self.end_states)
        if self.at_completed_states():
            changed_time, str_changed_time = self.get_time_n_str(changed)
            raw['created'] = str_created_time
            raw['key'] = self.issue.key
            raw['name'] = author
            raw['completed'] = str_changed_time
            raw['duration'] = duration_days(created_time, changed_time)
            raw['status'] = self.get_status_name()
            raw['summary'] = self.issue.fields.summary
            raw['applied_model'] = self.issue.raw['fields']["customfield_11822"]
            raw['build_number'] = self.issue.raw['fields']["customfield_11807"]
            raw['product'], raw['platform'], raw['version_n_build'], raw['version_begin'] = parse_store_publish_process(self.issue.key, 
                                                                                                  self.issue.raw['fields']["customfield_11822"],
                                                                                                  self.issue.raw['fields']["customfield_12036"],
                                                                                                  self.issue.raw['fields']["customfield_11807"],
                                                                                                  self.issue.raw['fields']["customfield_11828"],
                                                                                                  self.issue.fields.summary)
        elif self.at_failed_states():
            changed_time, str_changed_time = self.get_time_n_str(changed)
            raw['created'] = str_created_time
            raw['key'] = self.issue.key
            '''
            raw['name'] = author
            raw['completed'] = str_changed_time
            raw['duration'] = duration_days(created_time, changed_time)
            '''
            raw['status'] = self.get_status_name()
            raw['summary'] = self.issue.fields.summary
            raw['applied_model'] = self.issue.raw['fields']["customfield_11822"]
            raw['build_number'] = self.issue.raw['fields']["customfield_11807"]
            raw['product'], raw['platform'], raw['version_n_build'], raw['version_begin'] = parse_store_publish_process(self.issue.key, 
                                                                                                  self.issue.raw['fields']["customfield_11822"],
                                                                                                  self.issue.raw['fields']["customfield_12036"],
                                                                                                  self.issue.raw['fields']["customfield_11807"],
                                                                                                  self.issue.raw['fields']["customfield_11828"],
                                                                                                  self.issue.fields.summary)
        else:
            raw['created'] = str_created_time
            raw['key'] = self.issue.key
            raw['status'] = self.get_status_name()
            raw['summary'] = self.issue.fields.summary
            raw['applied_model'] = self.issue.raw['fields']["customfield_11821"]
            raw['build_number'] = self.issue.raw['fields']["customfield_11807"]
            raw['product'], raw['platform'], raw['version_n_build'], raw['version_begin'] = parse_store_publish_process(self.issue.key, 
                                                                                                  self.issue.raw['fields']["customfield_11821"],
                                                                                                  self.issue.raw['fields']["customfield_12036"],
                                                                                                  self.issue.raw['fields']["customfield_11807"],
                                                                                                  self.issue.raw['fields']["customfield_11828"],
                                                                                                  self.issue.fields.summary)
        if self.b_resolved:
            raw['done'] = 'Yes'
        else:
            raw['done'] = 'No'
        # self.debuglog_v(json.dumps(raw, indent=4))
        return raw

    def run(self, root_issue, parent_issue, data, downloads, b_update=False):
        self.debuglog_i('  [STORE PUBLISH-{key}] Run'.format(key=self.issue.key))
        self.trace_dependency()
        raw = self.get_gsheet_raw()
        if self.at_completed_states():
            self.b_resolved = True
            product = raw['product']
            platform = raw['platform']
            ver_n_bld = raw['version_n_build']
            resolutiondate_str = self.issue.fields.resolutiondate[:10]
            self.debuglog_r('     ┌* [STORE PUBLISH-{key}] - [{product}][{platform}][{ver_n_bld}][{resolutiondate_str}] CLOSE'.format(key=self.issue.key, product=product, platform=platform, ver_n_bld=ver_n_bld, resolutiondate_str=resolutiondate_str))
        elif self.at_failed_states():
            self.b_resolved = False
            the_time, str_time = self.get_created_n_str()
            model, product, ver=extract_model(root_issue.issue.fields.summary)
            self.debuglog_r('     ┌> [STORE PUBLISH-{key}] - [{product}] - [APP Release-{parent_key}] going'.format(key=self.issue.key, parent_key=parent_issue.issue.key, product=product), since=the_time)
        elif self.get_status_name() in ['abort']:
            self.b_resolved = True
            the_time, str_time = self.get_created_n_str()
            model, product, ver=extract_model(root_issue.issue.fields.summary)
            self.debuglog_r('     ┌* [STORE PUBLISH-{key}] - [{product}] - [APP Release-{parent_key}] ABORT'.format(key=self.issue.key, parent_key=parent_issue.issue.key, product=product), since=the_time)
        else:
            self.b_resolved = False
            the_time, str_time = self.get_created_n_str()
            model, product, ver=extract_model(root_issue.issue.fields.summary)
            self.debuglog_r('     ┌> [STORE PUBLISH-{key}] - [{product}] - [APP Release-{parent_key}] going'.format(key=self.issue.key, parent_key=parent_issue.issue.key, product=product), since=the_time)
        # self.gsheet.fw_del_proc(root_issue.issue, raw)
        return raw

    def check(self, root_issue, parent_issue, data, downloads, b_update=False):
        return self.run(root_issue, parent_issue, data, downloads, b_update=b_update)
        
        