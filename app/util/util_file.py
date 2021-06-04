#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  Duffy ver. 2.0
# Date:     2017/12/15
# 
import errno, gzip, json, os, re, sys

def silentremove(filename):
    try:
        os.remove(filename)
    except OSError as e: # this would be "except OSError, e:" before Python 2.6
        if e.errno != errno.ENOENT: # errno.ENOENT = no such file or directory
            raise # re-raise exception if a different error occured

def clean_local_folder(dir):
    for the_file in os.listdir(dir):
        file_path = os.path.join(dir, the_file)
        try:
            if os.path.isfile(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path): 
                shutil.rmtree(file_path)
        except Exception as e:
            print(e)
    
    
def get_name_list_of_files(dir):
    files = [f for f in os.listdir(dir) if os.path.isfile(os.path.join(dir, f))]
    return files
    
    
def get_sub_folder_list(dir):
    sub_folders = [f for f in os.listdir(dir) if not os.path.isfile(os.path.join(dir, f))]
    return sub_folders
   

def open_gzip_json(filename):
    return open_gzipfile_with_single_json(filename)
   

def open_gzip_multi_json(filename):
    return open_gzipfile_with_multi_line_json(filename)
   
def open_json(filename):
    with open(filename) as data_file:
    	data = json.load(data_file)
    return data
   
def open_gzipfile_with_single_json(filename):
    data = None
    with gzip.open(filename, 'rb') as f:
        file_content = f.read()
        try:
            data = json.loads(file_content)
        except ValueError as e:
            print("\t\texception [ValueError] at parsing [{filename}]".format(filename=filename))
            data = None
    return data
   
def open_gzipfile_with_multi_line_json(filename):
    data = []
    with gzip.open(filename, 'rb') as f:
        file_contents = f.readlines()
        for file_content in file_contents:
            try:
                data.append(json.loads(file_content))
            except ValueError as e:
                print("\t\texception [ValueError] at parsing [{filename}]".format(filename=filename))
                data = None
    return data
    
def dump_json(data):
    return json.dumps(data, sort_keys=True, indent=4, separators=(',', ': '), ensure_ascii=False).encode('utf8')
    