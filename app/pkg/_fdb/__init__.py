# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 2.0
# Date:     2022-04-05
#
import os, json

from pkg._util.util_file import create_folder
from pkg._util.util_text_file import open_json, dump_json

class i_fdb():
    def __init__(self, data=None, downloads=None, service='jira'):
        if downloads:
            dir_location = downloads + '/'
            create_folder(dir_location)
            dir_location = dir_location + '/' + service
            create_folder(dir_location)
        self.data = data
        self.downloads = downloads

    def file_location(self, key, service='jira'):
        if self.downloads:
            file_location = self.downloads + '/' + service + '/' + key
            return file_location
        return None

class permanent_obj(i_fdb):
    def __init__(self, data=None, downloads=None, filename=None, service='jira'):
        super(permanent_obj, self).__init__(data, downloads, service)
        self.service = service
        self.filename = filename
        self.json_obj = None

    def load(self, issuekey):
        if self.downloads:
            create_folder(self.file_location(issuekey, self.service))
        if self.filename and self.json_obj is None:
            filename = self.file_location(issuekey, self.service) + '/' + self.filename
            if os.path.isfile(filename):
                self.json_obj = open_json(filename)
        return self.json_obj

    def flush(self, issuekey):
        if self.downloads:
            create_folder(self.file_location(issuekey, self.service))
        if self.filename and self.json_obj:
            filename = self.file_location(issuekey, self.service) + '/' + self.filename
            dump_json(filename, self.json_obj)

    def update(self, issuekey, json_obj):
        if json_obj is None:
            return
        origin = self.load(issuekey)
        if origin:
            self.json_obj = origin | json_obj
        else:
            self.json_obj = json_obj
        self.flush(issuekey)

    def get(self):
        return self.json_obj

    def is_existing(self, issuekey):
        create_folder(self.file_location(issuekey, self.service))
        filename = self.file_location(issuekey, self.service) + '/' + self.filename
        return os.path.isfile(filename)

    def is_json_changed(self, issuekey, json_obj):
        if json_obj is None:
            return False
        if self.downloads and self.filename:
            create_folder(self.file_location(issuekey, self.service))
            filename = self.file_location(issuekey, self.service) + '/' + self.filename
            if os.path.isfile(filename):
                origin = open_json(filename)
                if origin and json.dumps(json_obj, sort_keys=True, indent=4)==json.dumps(origin, sort_keys=True, indent=4):
                    return False
                else:
                    return True
            else:
                return True
        else:
            return True

    def dump(self):
        print('--- FDB Dump')
        print('      filename: ' + self.filename)
        print('      json_obj: ' + str(self.json_obj))


class permanent_objException(Exception):
    def __init__(self, message, json_obj=None):
        super().__init__(message)
        self.json_obj = json_obj
