# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 2.1
# Date:     2023-09-25
#
from . import permanent_obj

class sf_raw(permanent_obj):
    ''' {
        },
    } '''
    def __init__(self, data, downloads, filename='sf_raw.json', service='sf'):
        super(sf_raw, self).__init__(data, downloads, filename, service)
