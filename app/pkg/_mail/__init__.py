# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 2.0
# Date:     2022-04-12
#
import json, os, sys, smtplib
import socket

from datetime import date
from pathlib import Path
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from pkg._util.util_file import create_folder
from pkg._util.util_text_file import open_json, dump_json

class i_mail():
    def __init__(self, 
                 subject, 
                 body, 
                 mail_from='stanleyshuang@qnap.com', 
                 mail_tos=['stanleyshuang@qnap.com'], 
                 attachments={}):
        self.subject = subject
        self.body = body
        self.mail_from = mail_from
        self.mail_tos = ", ".join(mail_tos)
        self.attachments = attachments

    def send(self):
        # Create a multipart message and set headers
        message = MIMEMultipart()
        message["From"] = self.mail_from
        message["To"] = self.mail_tos
        message["Subject"] = self.subject

        # Add body to email
        message.attach(MIMEText(self.body, "plain"))

        for attachment in self.attachments:
            with open(attachment['path'], "r") as fd:
                attachment_content = fd.read()

            # Add file as application/octet-stream
            # Email client can usually download this automatically as attachment
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment_content)

            # Encode file in ASCII characters to send by email    
            encoders.encode_base64(part)

            # Add header as key/value pair to attachment part
            part.add_header(
                "Content-Disposition",
                "attachment; filename= {name}".format(name=attachment['name']),
            )

            # Add attachment to message and convert message to string
            message.attach(part)

        text = message.as_string()

        print('server.sendmail(\n'
              '\tfrom:    {mail_from},\n'
              '\tto:      {mail_tos},\n'
              '\tsubject: {subject}\n'
              '\tbody:    {body}\n)'.format(
                mail_from=self.mail_from,
                mail_tos=self.mail_tos,
                subject=self.subject,
                body=self.body))
        if socket.gethostname()=='Bifrost871':
            # Log in to server using secure context and send email
            # smtp365.ieiworld.com: SNMP Server domain, 跟 IT 申請
            with smtplib.SMTP('smtp365.ieiworld.com', 25) as server:
                server.sendmail(self.mail_from, self.mail_tos, text)

