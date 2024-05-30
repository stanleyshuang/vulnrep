#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   StanleyS Huang
# Project:  mantisanalyzer 1.0
# Date:     2021-12-04
#
def _init():
    global _global_dict
    _global_dict = {}

def set_value(name, value):
    _global_dict[name] = value

def get_value(name, defValue=None):
    try:
        return _global_dict[name]
    except KeyError:
        return defValue