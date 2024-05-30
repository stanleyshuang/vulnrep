#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  py_lib 1.0
# Date:     2022-03-23
#
from datetime import datetime
from pkg._util.util_datetime import duration_days

class obj():

    def __init__(self, debug_mode='regular'):
        self.debug_mode = debug_mode

    def debuglog_r(self, message, since=None):
        if self.debug_mode in ['regular', 'iteration', 'verbose']:
            if since:
                now = datetime.now()
                print(message + ' (' + str(duration_days(since, now)) + ')')
            else:
                print(message)

    def debuglog_i(self, message, since=None):
        if self.debug_mode in ['iteration', 'verbose']:
            if since:
                now = datetime.now()
                print(message + ' (' + str(duration_days(since, now)) + ')')
            else:
                print(message)

    def debuglog_v(self, message, since=None):
        if self.debug_mode in ['verbose']:
            if since:
                now = datetime.now()
                print(message + ' (' + str(duration_days(since, now)) + ')')
            else:
                print(message)