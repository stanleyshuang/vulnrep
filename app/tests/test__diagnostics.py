# -*- coding: utf-8 -*-
#
# Author:   Stanley Huang
# Project:  mantisanalysis ver. 1.0
# Date:     2021-11-27
#
import unittest
from datetime import datetime
from pkg._mantis.diagnostics import parse_infection_date, qts_install_time_core

class ParseInfectionDateTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_parse_infection_date_10(self):
        the_date = parse_infection_date('infection date: 2021/12/8')
        self.assertTrue(the_date==datetime(2021, 12, 8))

    def test_parse_infection_date_20(self):
        the_date = parse_infection_date('infection date: 2021-9-18')
        self.assertTrue(the_date==datetime(2021, 9, 18))

    def test_parse_infection_date_30(self):
        the_date = parse_infection_date('infection date 2021/12/8')
        self.assertTrue(the_date==datetime(2021, 12, 8))

    def test_parse_infection_date_40(self):
        the_date = parse_infection_date('infection date 2021-9-18')
        self.assertTrue(the_date==datetime(2021, 9, 18))

    def test_parse_infection_date_50(self):
        the_date = parse_infection_date('infection-date 2021-11-17')
        self.assertTrue(the_date==datetime(2021, 11, 17))

    def test_parse_infection_date_60(self):
        the_date = parse_infection_date('infection_date 2020-11-17')
        self.assertTrue(the_date==datetime(2020, 11, 17))

    def test_parse_infection_date_70(self):
        the_date = parse_infection_date('infection_date: 2022/01/07')
        self.assertTrue(the_date==datetime(2022, 1, 7))

class ParseQtsInstallTimeCoreTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_qts_install_time_core_10(self):
        config = {'Date': '2022-05-23'}
        lines = [
            'Model: TS-253Be\n',
            'Firmware: 5.0.0_20220324\n',
            'Date: 20220501-23:36:22\n', 
            '============= [ EVENT LOG ]  <a href="#top">[ TOP ]</a>\n',
            '10730,  0,2022-01-30,07:08:55,System,127.0.0.1,localhost,[myQNAPcloud] myQNAPcloud Link service for myQNAPcloud website is ready., 31,1643548135,A041,myQNAPcloud,C003,myQNAPcloud Link,\n',
            '10731,  0,2022-01-30,20:25:08,admin,192.168.1.26,---,[Firmware Update] Started downloading firmware 5.0.0.1891 Build 20211221., 23,1643595908,A009,Firmware Update,C001,Firmware Update,\n',
            '10732,  0,2022-01-30,20:25:54,admin,192.168.1.26,---,[Firmware Update] Started unzipping TS-X53B_20211221-5.0.0.1891.zip., 18,1643595954,A009,Firmware Update,C001,Firmware Update,\n',
            '10733,  0,2022-01-30,20:26:00,admin,192.168.1.26,---,[Firmware Update] Started updating firmware 5.0.0.1891 Build 20211221., 20,1643595960,A009,Firmware Update,C001,Firmware Update,\n',
            '10734,  0,2022-01-30,20:26:23,System,127.0.0.1,localhost,[Firmware Update] Started updating firmware., 30,1643595983,A009,Firmware Update,C001,Firmware Update,\n',
            '10735,  0,2022-01-30,20:27:09,System,127.0.0.1,localhost,[Firmware Update] Updated system from version 4.5.4.1800(20210923) to 5.0.0.1891(20211221)., 28,1643596029,A009,Firmware Update,C001,Firmware Update,\n',
            '10736,  0,2022-01-30,20:27:11,admin,192.168.1.26,---,[Power] Restarting NAS.,  1,1643596031,A007,Power,C001,NAS Power Status,\n',
            '12053,  1,2022-05-01,08:00:00,System,127.0.0.1,localhost,[Security Counselor] Security Checkup hasn\'t run in over 30 days. Last scan was on "2022/01/30".,  9,1651410000,A254,Security Counselor,C001,Security Checkup,\n',
            '12054,  0,2022-05-01,23:06:23,admin,173.28.182.254,---,[Firmware Update] Started downloading firmware 5.0.0.1986 Build 20220324., 23,1651464383,A009,Firmware Update,C001,Firmware Update,\n',
            '12055,  0,2022-05-01,23:06:57,admin,173.28.182.254,---,[Firmware Update] Started unzipping TS-X53B_20220324-5.0.0.1986.zip., 18,1651464417,A009,Firmware Update,C001,Firmware Update,\n',
            '12056,  0,2022-05-01,23:07:00,admin,173.28.182.254,---,[Firmware Update] Started updating firmware 5.0.0.1986 Build 20220324., 20,1651464420,A009,Firmware Update,C001,Firmware Update,\n',
            '12057,  0,2022-05-01,23:07:17,System,127.0.0.1,localhost,[Firmware Update] Started updating firmware., 30,1651464437,A009,Firmware Update,C001,Firmware Update,\n',
            '12058,  0,2022-05-01,23:08:02,System,127.0.0.1,localhost,[Firmware Update] Updated system from version 5.0.0.1932(20220129) to 5.0.0.1986(20220324)., 28,1651464482,A009,Firmware Update,C001,Firmware Update,\n',
            '12059,  0,2022-05-01,23:09:03,admin,173.28.182.254,---,[Power] Restarting NAS.,  1,1651464543,A007,Power,C001,NAS Power Status,\n',
            '============= [ CONNECTION LOG ]  <a href="#top">[ TOP ]</a>\n',
        ]
        incident_date = datetime.strptime('2022-05-02', '%Y-%m-%d')
        config = qts_install_time_core('91837', config, lines, [], incident_date)
        self.assertTrue(config['Date']=='20220501-23:36:22' and
                        config['Model']=='TS-253Be' and
                        config['Firmware']=='[#91837] [2022-05-01] QTS 5.0.0.1986(20220324)' and
                        config['EventLogsLines']=='event-log-line# [15]')

    def test_qts_install_time_core_20(self):
        config = {'Date': '2022-05-23'}
        lines = [
            'Model: TS-253Be\n',
            'Firmware: 5.0.0_20220324\n',
            'Date: 20220501-23:36:22\n', 
            '============= [ EVENT LOG ]  <a href="#top">[ TOP ]</a>\n',
            '10730,  0,2022-01-30,07:08:55,System,127.0.0.1,localhost,[myQNAPcloud] myQNAPcloud Link service for myQNAPcloud website is ready., 31,1643548135,A041,myQNAPcloud,C003,myQNAPcloud Link,\n',
            '10731,  0,2022-01-30,20:25:08,admin,192.168.1.26,---,[Firmware Update] Started downloading firmware 5.0.0.1891 Build 20211221., 23,1643595908,A009,Firmware Update,C001,Firmware Update,\n',
            '10732,  0,2022-01-30,20:25:54,admin,192.168.1.26,---,[Firmware Update] Started unzipping TS-X53B_20211221-5.0.0.1891.zip., 18,1643595954,A009,Firmware Update,C001,Firmware Update,\n',
            '10733,  0,2022-01-30,20:26:00,admin,192.168.1.26,---,[Firmware Update] Started updating firmware 5.0.0.1891 Build 20211221., 20,1643595960,A009,Firmware Update,C001,Firmware Update,\n',
            '10734,  0,2022-01-30,20:26:23,System,127.0.0.1,localhost,[Firmware Update] Started updating firmware., 30,1643595983,A009,Firmware Update,C001,Firmware Update,\n',
            '10735,  0,2022-01-30,20:27:09,System,127.0.0.1,localhost,[Firmware Update] Updated system from version 4.5.4.1800(20210923) to 5.0.0.1891(20211221)., 28,1643596029,A009,Firmware Update,C001,Firmware Update,\n',
            '10736,  0,2022-01-30,20:27:11,admin,192.168.1.26,---,[Power] Restarting NAS.,  1,1643596031,A007,Power,C001,NAS Power Status,\n',
            '12053,  1,2022-05-01,08:00:00,System,127.0.0.1,localhost,[Security Counselor] Security Checkup hasn\'t run in over 30 days. Last scan was on "2022/01/30".,  9,1651410000,A254,Security Counselor,C001,Security Checkup,\n',
            '12054,  0,2022-05-01,23:06:23,admin,173.28.182.254,---,[Firmware Update] Started downloading firmware 5.0.0.1986 Build 20220324., 23,1651464383,A009,Firmware Update,C001,Firmware Update,\n',
            '12055,  0,2022-05-01,23:06:57,admin,173.28.182.254,---,[Firmware Update] Started unzipping TS-X53B_20220324-5.0.0.1986.zip., 18,1651464417,A009,Firmware Update,C001,Firmware Update,\n',
            '12056,  0,2022-05-01,23:07:00,admin,173.28.182.254,---,[Firmware Update] Started updating firmware 5.0.0.1986 Build 20220324., 20,1651464420,A009,Firmware Update,C001,Firmware Update,\n',
            '12057,  0,2022-05-01,23:07:17,System,127.0.0.1,localhost,[Firmware Update] Started updating firmware., 30,1651464437,A009,Firmware Update,C001,Firmware Update,\n',
            '12058,  0,2022-05-01,23:08:02,System,127.0.0.1,localhost,[Firmware Update] Updated system from version 5.0.0.1932(20220129) to 5.0.0.1986(20220324)., 28,1651464482,A009,Firmware Update,C001,Firmware Update,\n',
            '12059,  0,2022-05-01,23:09:03,admin,173.28.182.254,---,[Power] Restarting NAS.,  1,1651464543,A007,Power,C001,NAS Power Status,\n',
            '============= [ CONNECTION LOG ]  <a href="#top">[ TOP ]</a>\n',
        ]
        incident_date = datetime.strptime('2022-03-15', '%Y-%m-%d')
        config = qts_install_time_core('91837', config, lines, [], incident_date)
        self.assertTrue(config['Date']=='20220501-23:36:22' and
                        config['Model']=='TS-253Be' and
                        config['Firmware']=='[#91837] [2022-01-30] QTS 5.0.0.1891(20211221)' and
                        config['EventLogsLines']=='event-log-line# [15]')

    def test_qts_install_time_core_30(self):
        config = {'Date': '2022-05-23'}
        lines = [
            'Model: TS-253Be\n',
            'Firmware: 5.0.0_20220324\n',
            'Date: 20220501-23:36:22\n', 
            '============= [ EVENT LOG ]  <a href="#top">[ TOP ]</a>\n',
            '10730,  0,2022-01-30,07:08:55,System,127.0.0.1,localhost,[myQNAPcloud] myQNAPcloud Link service for myQNAPcloud website is ready., 31,1643548135,A041,myQNAPcloud,C003,myQNAPcloud Link,\n',
            '10731,  0,2022-01-30,20:25:08,admin,192.168.1.26,---,[Firmware Update] Started downloading firmware 5.0.0.1891 Build 20211221., 23,1643595908,A009,Firmware Update,C001,Firmware Update,\n',
            '10732,  0,2022-01-30,20:25:54,admin,192.168.1.26,---,[Firmware Update] Started unzipping TS-X53B_20211221-5.0.0.1891.zip., 18,1643595954,A009,Firmware Update,C001,Firmware Update,\n',
            '10733,  0,2022-01-30,20:26:00,admin,192.168.1.26,---,[Firmware Update] Started updating firmware 5.0.0.1891 Build 20211221., 20,1643595960,A009,Firmware Update,C001,Firmware Update,\n',
            '10734,  0,2022-01-30,20:26:23,System,127.0.0.1,localhost,[Firmware Update] Started updating firmware., 30,1643595983,A009,Firmware Update,C001,Firmware Update,\n',
            '10735,  0,2022-01-30,20:27:09,System,127.0.0.1,localhost,[Firmware Update] Updated system from version 4.5.4.1800(20210923) to 5.0.0.1891(20211221)., 28,1643596029,A009,Firmware Update,C001,Firmware Update,\n',
            '10736,  0,2022-01-30,20:27:11,admin,192.168.1.26,---,[Power] Restarting NAS.,  1,1643596031,A007,Power,C001,NAS Power Status,\n',
            '12053,  1,2022-05-01,08:00:00,System,127.0.0.1,localhost,[Security Counselor] Security Checkup hasn\'t run in over 30 days. Last scan was on "2022/01/30".,  9,1651410000,A254,Security Counselor,C001,Security Checkup,\n',
            '12054,  0,2022-05-01,23:06:23,admin,173.28.182.254,---,[Firmware Update] Started downloading firmware 5.0.0.1986 Build 20220324., 23,1651464383,A009,Firmware Update,C001,Firmware Update,\n',
            '12055,  0,2022-05-01,23:06:57,admin,173.28.182.254,---,[Firmware Update] Started unzipping TS-X53B_20220324-5.0.0.1986.zip., 18,1651464417,A009,Firmware Update,C001,Firmware Update,\n',
            '12056,  0,2022-05-01,23:07:00,admin,173.28.182.254,---,[Firmware Update] Started updating firmware 5.0.0.1986 Build 20220324., 20,1651464420,A009,Firmware Update,C001,Firmware Update,\n',
            '12057,  0,2022-05-01,23:07:17,System,127.0.0.1,localhost,[Firmware Update] Started updating firmware., 30,1651464437,A009,Firmware Update,C001,Firmware Update,\n',
            '12058,  0,2022-05-01,23:08:02,System,127.0.0.1,localhost,[Firmware Update] Updated system from version 5.0.0.1932(20220129) to 5.0.0.1986(20220324)., 28,1651464482,A009,Firmware Update,C001,Firmware Update,\n',
            '12059,  0,2022-05-01,23:09:03,admin,173.28.182.254,---,[Power] Restarting NAS.,  1,1651464543,A007,Power,C001,NAS Power Status,\n',
            '============= [ CONNECTION LOG ]  <a href="#top">[ TOP ]</a>\n',
        ]
        incident_date = datetime.strptime('2022-01-15', '%Y-%m-%d')
        config = qts_install_time_core('91837', config, lines, [], incident_date)
        self.assertTrue(config['Date']=='20220501-23:36:22' and
                        config['Model']=='TS-253Be' and
                        config['Firmware']=='[#91837] [2022-05-23] 5.0.0_20220324' and
                        config['EventLogsLines']=='event-log-line# [15]')

