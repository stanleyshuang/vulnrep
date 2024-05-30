#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2021-10-12
#
class debug:
    def __init__(self, debug_mode):
        self.output_buff = ''
        self.debug_mode = debug_mode

    def log_r(self, message):
        if self.debug_mode in ['regular', 'iteration', 'verbose']:
            self.output_buff += message + '\n'
            print(message)

    def log_i(self, message):
        if self.debug_mode in ['iteration', 'verbose']:
            self.output_buff += message + '\n'
            print(message)

    def log_v(self, message):
        if self.debug_mode in ['verbose']:
            self.output_buff += message + '\n'
            print(message)
