# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  Duffy ver. 2.0
# Date:     2017/12/15
# 
from datetime import datetime
from dateutil import tz
from dateutil.relativedelta import relativedelta

class UtilTz:
    tz_dict = {'Asia/Taipei': 'Taipei',
               'America/New_York': 'New York'}
       
    def code_to_description(self, tz):
        if tz and self.tz_dict.get(tz):
            return self.tz_dict[tz]
        else:
            return 'Taipei'


def utc_to_local_str(utc_datetime, local_tz_str='Asia/Taipei', format='%Y/%m/%d %H:%M:%S'):
    local_zone = tz.gettz(local_tz_str)
    if local_zone and utc_datetime:
        utc_datetime = utc_datetime.replace(tzinfo=tz.tzutc())
        local_datetime = utc_datetime.astimezone(local_zone)
        return local_datetime.strftime(format)
    return 'N/A'


def utc_to_local(utc_datetime, local_tz_str='Asia/Taipei'):
    local_zone = tz.gettz(local_tz_str)
    if local_zone and utc_datetime:
        utc_datetime = utc_datetime.replace(tzinfo=tz.tzutc())
        local_datetime = utc_datetime.astimezone(local_zone)
        return local_datetime
    return None
    
    
def local_str_to_utc(local_datetime_str, local_tz_str='Asia/Taipei', format='%Y/%m/%d %H:%M:%S'):
    local_datetime = datetime.strptime(local_datetime_str, format)
    local_zone = tz.gettz(local_tz_str)
    if local_zone:
        local_datetime = local_datetime.replace(tzinfo=local_zone)
        utc_datetime = local_datetime.astimezone(tz.tzutc())
        return utc_datetime
    return None
    
    
def local_to_utc(local_datetime, local_tz_str='Asia/Taipei'):
    local_zone = tz.gettz(local_tz_str)
    if local_zone:
        local_datetime = local_datetime.replace(tzinfo=local_zone)
        utc_datetime = local_datetime.astimezone(tz.tzutc())
        format='%Y-%m-%d %H:%M:%S'
        utc_datetime = datetime.strptime(utc_datetime.strftime(format), format)
        return utc_datetime
    return None


def pick_current_day_1st_sec(original_datetime):
    d = original_datetime
    new_datetime = datetime(d.year, d.month, d.day)
    return new_datetime


def pick_coming_year_day_one(original_datetime):
    d = original_datetime + relativedelta(years=1) + relativedelta(months=1) - relativedelta(seconds=1)
    new_datetime = datetime(d.year, d.month, 1)
    return new_datetime


def pick_n_days_before(original_datetime, n_days):
    d = original_datetime - relativedelta(days=n_days)
    new_datetime = datetime(d.year, d.month, d.day)
    return new_datetime


def pick_n_days_after(original_datetime, n_days):
    d = original_datetime + relativedelta(days=n_days)
    new_datetime = datetime(d.year, d.month, d.day)
    return new_datetime


def pick_n_months_before(original_datetime, n_months):
    d = original_datetime - relativedelta(months=n_months)
    new_datetime = datetime(d.year, d.month, d.day)
    return new_datetime


def pick_n_months_after(original_datetime, n_months):
    d = original_datetime + relativedelta(months=n_months)
    new_datetime = datetime(d.year, d.month, d.day)
    return new_datetime


def pick_30_days_before(original_datetime):
    return pick_n_days_before(original_datetime, 30)


def pick_90_days_before(original_datetime):
    return pick_n_days_before(original_datetime, 90)


def pick_30_days_after(original_datetime):
    return pick_n_days_after(original_datetime, 30)


def pick_current_month_day_one(original_datetime):
    new_datetime = datetime(original_datetime.year, original_datetime.month, 1)
    return new_datetime


def pick_coming_month_day_one(original_datetime):
    d = original_datetime + relativedelta(months=1)
    new_datetime = datetime(d.year, d.month, 1)
    return new_datetime


def pick_three_months_day_one(original_datetime):
    d = original_datetime + relativedelta(months=3)
    new_datetime = datetime(d.year, d.month, d.day)
    return new_datetime


def pick_previous_month_last_day(original_datetime):
    d = original_datetime
    new_datetime = datetime(d.year, d.month, 1) - relativedelta(seconds=1)
    return new_datetime


def pick_current_month_last_day(original_datetime):
    d = original_datetime + relativedelta(months=1)
    new_datetime = datetime(d.year, d.month, 1) - relativedelta(seconds=1)
    return new_datetime


def pick_coming_month_last_day(original_datetime):
    d = original_datetime + relativedelta(months=2)
    new_datetime = datetime(d.year, d.month, 1) - relativedelta(seconds=1)
    return new_datetime


def pick_latest_date(original_datetime, new_datetime):
    delta = new_datetime - original_datetime
    diff_days = delta.days
    if diff_days > 0:
        return new_datetime
    else:
        return original_datetime


def within_30_days_before(original_datetime, target_datetime):
    delta = target_datetime - original_datetime
    diff_days = delta.days
    if diff_days > 0:
        return False

    d = original_datetime - relativedelta(days=30)
    the_30_days_before_datetime = datetime(d.year, d.month, d.day)

    delta = target_datetime - the_30_days_before_datetime
    diff_days = delta.days
    if diff_days >= 0:
        return True
    return False