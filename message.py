#   Copyright 2016 Massachusetts Open Cloud
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.
"""Mechanism for composing and sending email messages."""
import os
import string
import smtplib
from email.mime.text import MIMEText
from moc_utils import get_absolute_path
from moc_exceptions import BadEmailRecipient


class Message(object):
    """Base class for email messages."""
    def __init__(self, sender, receiver, body, subject=None, cc_list=None,
                 formatting='plain'):
        self.sender = sender
        self.receiver = receiver
        self.cc_list = cc_list
        self.subject = subject
        self.body = body
        self._format = formatting

    def _personalize(self, template, **kwargs):
        """Populate the given email template with customized values
         
        Assumes that the template placeholders are uppercased argument
        keywords enclosed by `<>`.
        """
        template = get_absolute_path(template)
        with open(template, "r") as f:
            msg = f.read()
        for key in kwargs:
            if kwargs[key] is not None:
                placeholder = "<{}>".format(key.upper())
                msg = string.replace(msg, placeholder, kwargs[key])
        return msg

    def dump_to_file(self, target_path='/tmp', label=None):
        """ Print email body to a file.
        
        Back up the personalized email message if the email cannot be sent.
        The output file is placed in the directory specified by target_path
        and labeled with the first portion of the email address and either
        the optional 'label' or the email subject.
        """
        if not label:
            label = self.subject
        email_parts = self.receiver.split('@')
        out_file = "{0}_{1}.txt".format(email_parts[0], label)
        
        file_path = get_absolute_path(os.path.join(target_path, out_file))
        
        with open(file_path, 'w') as f:
            f.write(self.body)
        f.close()
        return file_path

    def send(self, mail_ip='127.0.0.1', mail_port='25'):
        """ Send the message """
        msg = MIMEText(self.body, self._format)
        msg['Subject'] = self.subject
        msg['From'] = self.sender
        msg['To'] = self.receiver
        receivers = [self.receiver]
        if self.cc_list:
            msg['Cc'] = self.cc_list
            receivers.append(self.cc_list)
            
        server = smtplib.SMTP(mail_ip, mail_port)
        server.ehlo()
        server.starttls()

        rejected = server.sendmail(self.sender, receivers, msg.as_string())
        # server.sendmail raises SMTPRecipientsRefused only if *all*
        # recipients fail and the email cannot be sent. Catch failure of
        # some but not all recipients:
        if len(rejected):
            raise BadEmailRecipient(rejected, msg['Subject'])


class TemplateMessage(Message):
    """Email message populated from a template file.
     
    Creates an email message by customizing a specified template. Assumes
    each keyword argument passed to self._personalize() corresponds to a
    placeholder in the template file with the form `<KEYWORD>`.
    """
    def __init__(self, template, sender, email, subject=None, cc_list=None,
                 formatting='plain', **kwargs):
        body = self._personalize(template, **kwargs)
        super(TemplateMessage, self).__init__(receiver=email,
                                              body=body,
                                              subject=subject,
                                              sender=sender,
                                              cc_list=cc_list,
                                              formatting=formatting)


class ListservMessage(Message):
    """Email message to subscribe a list of emails to a mailing list.
    
    Each line of the email is constructed using the specified template file.
    """
    def __init__(self, users, template, sender, majordomo, **kwargs):
        body = self._subscriptions(users, template, **kwargs)
        super(ListservMessage, self).__init__(sender, majordomo, body)

    def _subscriptions(self, users, template, **kwargs):
        """Generate the subscription email body, one line per user"""
        msg = ""
        for user in users:
            line = self._personalize(template=template,
                                     email=user,
                                     **kwargs)
            msg = "\n".join([msg, line.strip()])
        return msg
