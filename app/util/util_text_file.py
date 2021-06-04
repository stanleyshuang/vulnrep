#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  helloworld 1.0
# Date:     2020-12-04
# 

def get_lines(filename):
    with open(filename, 'r') as fp:
         all_lines = fp.readlines()
         return all_lines
    return None
