#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 2.0
# Date:     2023-02-03
#
import os, shutil

from pkg._cve.json_4_0 import json_4_0
from pkg._util.util_file import create_folder


class json_3rdparty(json_4_0):
    def __init__(self, issuekey, qsa, gsheet, qsa_id, summary):
        super(json_4_0, self).__init__(issuekey, qsa, gsheet, qsa_id, summary)

    @property
    def filename(self):
        return self.qsa_id
