# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  Duffy ver. 2.0
# Date:     2017/12/15
# 
from flask import current_app, url_for
import pyqrcode
import os.path
    
    
def make_qrcode(img_name, related_path, qrcode_content, scale=1):
    # related_path is beginning at '/app/static/upload'
    path = current_app.config['DESTINATION_ROOT_FOLDER'] + related_path + '/' + img_name
    if not os.path.isfile(path):
        qrcode = pyqrcode.create(qrcode_content, error='L')
        qrcode.svg(path, scale)
    qrcode_svg = url_for('static', filename='upload' + related_path + '/' + img_name)
    return (qrcode_svg, qrcode_content)