# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 2.0
# Date:     2022-04-17
#
import os
from . import permanent_obj

class vnotification_email(permanent_obj):
    def __init__(self, data, downloads, filename='notification_email.json'):
        super(vnotification_email, self).__init__(data, downloads, filename)

    def create(self, issuekey, sf_data, summary, qsaid, researcher_name, qsa):
        from datetime import datetime
        from pkg._util.util_datetime import utc_to_local_str

        if 'cve_publish' in qsa and len(qsa['cve_publish'])>0:
            str_date_piblic = qsa['cve_publish']
        else:
            now = datetime.now()
            str_date_piblic = utc_to_local_str(now, 'Asia/Taipei', format='%Y-%m-%d')

        # subject
        if 'sf_case_num' in sf_data:
            case_num = sf_data['sf_case_num']
        else:
            case_num = ''
        subject = '{case_num} {subject}'.format(case_num=case_num, subject=summary)
        url = 'https://www.qnap.com/en/security-advisory/' + qsaid.lower()

        # receiver
        receiver = sf_data['researcher_email']

        # mail_body
        mail_template = 'Dear {researcher_name},\n\n' \
                        'Thank you very much again for your valuable contribution.\n\n' \
                        'We plan to publish the security advisory addressing the vulnerability you found. It will be found at:\n' \
                        '{url}\n\n' \
                        'If you have any questions, please feel free to reply directly.\n\n' \
                        'Best regards,\nQNAP PSIRT'

        body = mail_template.format(researcher_name=researcher_name, url=url)
        url = os.environ.get('jira_url') + '/browse/' + issuekey
        the_mail = {
            'url': url,
            'date': str_date_piblic,
            'subject': subject,
            'receiver': receiver,
            'body': body
        }
        self.update(issuekey, the_mail)

        from pkg._mail import i_mail
        notification_body = body + '\n---\n' + receiver + '\n---\n' + str_date_piblic
        mail = i_mail(subject, notification_body)
        mail.send()
