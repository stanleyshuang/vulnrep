#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  honey 1.0
# Date:     2022-03-19
#
import json
import requests

class abuseipdb():
    ### Defining the api-endpoint
    ca_url = 'https://api.abuseipdb.com/api/v2/check'
    ca_abuseipdb_key = 'be41077eab24070d4e1d7679d35842604982b3db76126c4facae79bf7feb96be81c01d71c6c280cf'
    
    def __init__(self):
        pass
    
    def check(self, ip_addr, str_max_age_in_days='90'):
        querystring = {
            'ipAddress': ip_addr,
            'maxAgeInDays': str_max_age_in_days
        }

        headers = {
            'Accept': 'application/json',
            'Key': abuseipdb.ca_abuseipdb_key
        }

        response = requests.request(method='GET', url=abuseipdb.ca_url, headers=headers, params=querystring)

        # Formatted output
        decodedResponse = json.loads(response.text)
        return decodedResponse

    def is_black_ip(self, decodedResponse, threshold=85):
        '''
        print(json.dumps(decodedResponse, sort_keys=True, indent=4))
        return
        {
            "data": {
                "abuseConfidenceScore": 100,
                "countryCode": "RO",
                "domain": "dmzhost.co",
                "hostnames": [
                    "edc11.app-autht.com"
                ],
                "ipAddress": "45.148.10.59",
                "ipVersion": 4,
                "isPublic": true,
                "isWhitelisted": false,
                "isp": "Pptechnology Limited",
                "lastReportedAt": "2022-03-19T06:56:21+00:00",
                "numDistinctUsers": 115,
                "totalReports": 534,
                "usageType": "Data Center/Web Hosting/Transit"
            }
        }
        '''
        if not decodedResponse or 'data' not in decodedResponse:
            return False, None
        else:
            data = decodedResponse['data']

            if 'ipAddress' not in data:
                return False, None

            ip_addr = data['ipAddress']

            score = 0
            b_public = False
            b_white_listed = True

            if 'isPublic' in data:
                b_public = data['isPublic']

            if 'isWhitelisted' in data:
                b_white_listed = data['isWhitelisted']

            if 'abuseConfidenceScore' in data:
                score = data['abuseConfidenceScore']

            if score>threshold and b_public and not b_white_listed:
                return True, ip_addr
            return False, ip_addr
        return False, None
