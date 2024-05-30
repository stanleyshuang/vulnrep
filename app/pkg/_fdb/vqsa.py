# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 2.0
# Date:     2022-04-17
#
from . import permanent_obj

class vqsa(permanent_obj):
    def __init__(self, data, downloads, filename='qsa.json'):
        super(vqsa, self).__init__(data, downloads, filename)

    def does_researcher_exist(self):
        return 'task' in self.json_obj and 'researcher_email' in self.json_obj['task'] and self.json_obj['task']['researcher_email'] and len(self.json_obj['task']['researcher_email'])>0

    def researcher_email(self):
        if self.does_researcher_exist():
            return self.json_obj['task']['researcher_email']
        else:
            return None
