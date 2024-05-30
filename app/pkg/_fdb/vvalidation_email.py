# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 2.0
# Date:     2022-04-17
#
import os
from . import permanent_obj

class vvalidation_email(permanent_obj):
    def __init__(self, data, downloads, filename='validation_email.json'):
        super(vvalidation_email, self).__init__(data, downloads, filename)

    def read(self, issuekey):
        self.load(issuekey)
        if not self.json_obj:
            return
        if 'url' in self.json_obj:
            print('[Jira Task] ' + self.json_obj['url'])
        if 'date' in self.json_obj:
            print('[Date] ' + self.json_obj['date'])
        if 'subject' in self.json_obj:
            print('[Subject] ' + self.json_obj['subject'])
        if 'body' in self.json_obj:
            print('[Body] ' + self.json_obj['body'])
        if 'sub_report_num' in self.json_obj:
            print('[Sub-report Number] ' + str(self.json_obj['sub_report_num']))
        print('----------------------------------------------------------------')

    def need_to_be_modified(self, issuekey, sub_report_num):
        if not self.is_existing(issuekey):
            return True
        else:
            self.load(issuekey)
            if not self.json_obj:
                return True
            elif 'sub_report_num' not in self.json_obj and sub_report_num>1:
                return True
            elif 'sub_report_num' in self.json_obj and sub_report_num>self.json_obj['sub_report_num']:
                return True
            elif 'body' in self.json_obj and self.json_obj['body'].find('CVSSv3 Score')<0:
                return True
            else:
                return False

    def create(self, issuekey, sf_data, jira_summary, sf_subject, b_plan_2_disclose, b_request_info, researcher_name, the_data):
        print('   寄出確認信')
        from pkg._qjira.description import extract_severity_level, severity_level_2_cvssv3_score, extract_cveid
        # subject
        if 'sf_case_num' in sf_data:
            case_num = sf_data['sf_case_num']
        else:
            case_num = ''
        subject = sf_subject

        # receiver
        receiver = sf_data['researcher_email']

        # mail_body
        mail_template = ('Dear {researcher_name},\n\n'
                        'Thank you for the diligent submission of vulnerability reports. After a meticulous review, our team has confirmed the validity of the initial triage results.\n'
                        'Here is the breakdown of the vulnerability report:\n\n'
                        '{vuln_analysis_statement}'  # 'Do you agree with the triage results?{plan_2_disclose}\n\n' \
                        '{outscope}' 
                        '{collect_personal_data}' 
                        'Should you need any further clarification or assistance, please don\'t hesitate to contact us. We are committed to providing support and addressing any concerns you may have.\n\n'
                        'Best regards,\nQNAP PSIRT\n\n')
        vuln_analysis_statement = ''
        if b_plan_2_disclose:
            plan_2_disclose = ' And do you plan to disclose the vulnerabilities?'
        else:
            plan_2_disclose = ''
        if not b_request_info:
            collect_personal_data = ''
        else:
            collect_personal_data = ('\nTo maintain a long-term relationship with you, we kindly request that you share the following information with us:\n\n'
                                        '1. Your full name\n'
                                        '2. The name you prefer to be called on Security Advisory\n'
                                        '3. The name of your company or school\n'
                                        '4. The city where you reside\n'
                                        '5. The URL of your LinkedIn profile or blog\n'
                                        '6. Your PayPal account information\n'
                                        '7. How you became aware of QNAP Security Bounty Program\n\n'
                                    'Please note that if your PayPal address differs from the email address used in the vulnerability report, we may need to undergo an additional verification process.\n\n')
        
        
        b_outscope = False
        validated = analysis = ''

        for data in the_data:
            if len(the_data)==1:
                summary = sf_subject
            else:
                summary = data['summary']
            validated = data['validated']
            analysis = data['analysis']

            subject_lower = data['summary'].lower()
            if subject_lower.find('[qts')<0 and \
               subject_lower.find('[quts hero')<0 and \
               subject_lower.find('[qutscloud')<0 and \
               subject_lower.find('[qnap cloud service]')<0 and \
               subject_lower.find('[cloud web]')<0 and \
               subject_lower.find('[qpkg')<0:
               b_outscope = True

            severity_level = extract_severity_level(jira_summary)
            low, high = severity_level_2_cvssv3_score(severity_level)

            # vuln_analysis_statement += '- {subject}\n'.format(subject=summary)
            vuln_analysis_statement += '- {case_num} {subject}\n' \
                                    '   Severity level: {severity_level}, with a CVSSv3 Score of {low} - {high}.\n'.format(
                                            case_num=case_num, 
                                            subject=summary,
                                            severity_level=severity_level,
                                            low=low,
                                            high=high)

            if 'description' in analysis.json_obj:
                vuln_analysis_statement += '   Quality of Description: Rated [' + str(analysis.json_obj['description']) + '] out of 5.\n'
            if 'poc' in analysis.json_obj:
                vuln_analysis_statement += '   Quality of POC: Scored [' + str(analysis.json_obj['poc']) + '] out of 5.\n'
            if 'suggestion' in analysis.json_obj:
                vuln_analysis_statement += '   Quality of Suggestion: Rated [' + str(analysis.json_obj['suggestion']) + '] out of 5.\n'

            cveids = extract_cveid(summary)
            if cveids:
                vuln_analysis_statement += '   [{cveid}] has been assigned.\n\n'.format(cveid='|'.join(cveids))
            else:
                vuln_analysis_statement += '\n'

        outscope = ''
        if b_outscope:
            outscope = ('Unfortunately, we must inform you that the reported vulnerability is not eligible for a reward as it falls outside the scope of our security bounty program. '
                        'We only accept vulnerability reports for QNAP products and services, and out-of-scope reports are not eligible for rewards unless they are critical and exceptional circumstances warrant their inclusion. '
                        'The affected locations are \n\n'
                        '- {$locations}\n\n'
                        'Although the reported vulnerability is not eligible for a reward under our program, we greatly appreciate the information you provided. To express our gratitude, we will still provide a monetary reward.')


        body = mail_template.format(researcher_name=researcher_name,
                                    vuln_analysis_statement=vuln_analysis_statement,
                                    collect_personal_data=collect_personal_data,
                                    plan_2_disclose=plan_2_disclose,
                                    outscope=outscope)
        url = os.environ.get('jira_url') + '/browse/' + issuekey
        the_mail = {
            'url': url,
            'date': validated,
            'subject': subject,
            'receiver': receiver,
            'body': body,
            'sub_report_num': len(the_data)
        }
        self.update(issuekey, the_mail)

        from pkg._mail import i_mail
        notification_body = body + '\n---\n' + receiver + '\n---\n' + validated
        mail = i_mail(subject, notification_body)
        mail.send()
