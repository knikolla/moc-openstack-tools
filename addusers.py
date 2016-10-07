__author__ = 'rahuls@ccs.neu.edu'

import os
import json
import string
import random
import re
import ConfigParser
from keystoneclient.v2_0 import client
from novaclient import client as novaclient
from neutronclient.v2_0 import client as neutronclient
from cinderclient.v2 import client as cinderclient

import smtplib
from email.mime.text import MIMEText

import parse_spreadsheet

CONFIG_FILE = "settings.ini"

config = ConfigParser.ConfigParser()
config.read(CONFIG_FILE)

admin_user = config.get('auth', 'admin_user')
admin_pwd = config.get('auth', 'admin_pwd')
admin_tenant = config.get('auth', 'admin_tenant')
auth_url = config.get('auth', 'auth_url')
region_name = config.get('auth', 'region_name') # not needed in Mitaka
nova_version = config.get('nova', 'version')

email_template = config.get('templates', 'email_template')
password_template = config.get('templates', 'password_template')

email_path = config.get('output', 'email_path')

class InvalidEmailError(Exception):
    """User's email address does not pass basic format validation"""

class BadEmailRecipient(InvalidEmailError):
    """If sending failed to one or more recipients, but not all of them."""
    def __init__(self, rdict, subject):
        self.rejected = rdict;
        self.message = "Message {0} could not be sent to one or more recipients.".format(subject)

def random_password(size):
    chars = string.ascii_letters + string.digits + string.punctuation[2:6]
    return ''.join(random.choice(chars) for _ in range(size))


class Openstack:

    def __init__(self, uname, password, tname, auth_url, nova_version):
        self.keystone = client.Client(username=uname,
                                      password=password,
                                      tenant_name=tname,
                                      auth_url=auth_url)
        self.nova = novaclient.Client(nova_version,
                                      uname,
                                      password,
                                      tname,
                                      auth_url)
    def validate_email(self, uname):
        """Check that the email address provided matches a few simple rules

        The email address should have no whitespace, exactly 1 '@' symbol, and
        at least one '.' following the @ symbol. 
        """
        pattern = re.compile('[^@\s]+@[^@\s]+\.[^@\s]+')
        if pattern.match(uname):
            return
        else:
            raise InvalidEmailError('Not a valid email address: {}'.format(uname))

        """
        region_name is passed to neutronclient to avoid this warning: 
             keystoneclient/service_catalog.py:196: UserWarning: Providing 
             attr without filter_value to get_urls() is deprecated as of 
             the 1.7.0 release and may be removed in the 2.0.0 release." 
             Either both should be provided or neither should be provided.
        Liberty neutronclient hard-codes passing the attr 'region' so we
        must supply the filter_value region_name.  This issue is fixed in
        Mitaka neutronclient.
        """
        self.neutron = neutronclient.Client(username=uname,
                                            password=password,
                                            tenant_name=tname,
                                            auth_url=auth_url,
                                            region_name=region_name)
        self.cinder = cinderclient.Client(uname,
                                          password,
                                          tname,
                                          auth_url)

    def create_project(self, name, description, quotas):
        tenants = [tenant.name.lower() for tenant in self.keystone.tenants.list()]
        name_low = name.lower()
        if name_low not in tenants:
            print "TENANT: %-30s   \tPRESENT: NO, CREATING IT" % name
            tenant = self.keystone.tenants.create(tenant_name=name,
                                                  description=description,
                                                  enabled=True)

            # we only want to set quotas for newly created projects
            self.modify_quotas(tenant.id, name, **quotas)
            return tenant.name, tenant.id
        else:
            print "TENANT: %-30s   \tPRESENT: YES" % name
            tenants = [(tenant.name, tenant.id) for tenant in self.keystone.tenants.list()]
            for tenant in tenants:
                if name_low == tenant[0]:
                    return tenant 

    def create_user(self, name, username, password, description, email, tenant_id, proj_name):
        users = [user.name for user in self.keystone.users.list()]
        if username not in users:
            print "\tUSER: %-30s    PRESENT: NO, CREATING IT" % username
            self.validate_email(username)    
            user = self.keystone.users.create(name=username,
                                              email=email,
                                              password=password,
                                              tenant_id=tenant_id)

            try:
                send_email(name, username, 'new_user', proj_name=proj_name)
            except:
                # save text of the password email too if welcome email fails
                msg = personalize_msg(password_template, name, username, proj_name, password)
                email_to_file(username, msg, 'password')
                raise

            send_email(name, username, 'password', password=password)

        else:
            print "\tUSER: %-30s    PRESENT: YES" % username

    def modify_quotas(self, tenant_id, tenant_name, **kwargs):
        """
        Set quota values for the given tenant.
        
        NOTE: Quotas are managed through their related service, but 
        novaclient.quotas.get() reports dummy values for the following
        even when neutron is managing networks:
            floating_ips, security_group_rules, security_groups
        
        If networks are managed by neutron, the values reported by nova are 
        not accurate, and updates made via novaclient have no effect
        """

        # Quotas managed by neutronclient
        neutron = [ 'subnet', 'network', 'floatingip', 'subnetpool', 
                'security_group_rule', 'security_group', 'router', 
                'rbac_policy', 'port' ]

        # Quotas managed by novaclient
        # TODO: Test whether novaclient manages these quotas:
        #    fixed_ips, server_group_members, server_groups
        nova = [ 'cores', 'injected_file_content_bytes', 
                 'inject_file_path_bytes', 'injected_files', 'instances', 
                 'key_pairs', 'metadata_items', 'ram' ]

        # Quotas managed by cinderclient
        cinder = [ 'gigabytes', 'snapshots', 'volumes', 'backup_gigabytes', 
                   'backups', 'per_volume_gigabytes' ]
 
        neutron_quotas = dict()
        nova_quotas = dict()
        cinder_quotas = dict()

        for key in kwargs:
            if key in neutron:
                neutron_quotas[key]=kwargs[key] 
            elif key in nova:
                nova_quotas[key]=kwargs[key]
            elif key in cinder: 
                cinder_quotas[key]=kwargs[key]
            else:
                print "\tWARNING: Unrecognized quota '{0}={1}'".format(
                        key, kwargs[key])
                
        neutron_quotas = { "quota" : neutron_quotas }
        new_neutron = self.neutron.update_quota(tenant_id, 
                body=neutron_quotas )       
        new_nova = self.nova.quotas.update(tenant_id, **nova_quotas)
        new_cinder = self.cinder.quotas.update(tenant_id, **cinder_quotas)

        # NOTE: liberty cinderclient is missing the to_dict method in 
        # class Resource in cinderclient/openstack/common/apiclient/base.py
        # This is fixed in Mitaka, but for now we need to use an internal 
        # attribute '._info'

        all_quotas = new_neutron['quota']
        all_quotas.update(new_nova.to_dict())
        all_quotas.update(new_cinder._info)
        print "Quotas: {0}\n".format(json.dumps(all_quotas))

def personalize_msg(template, fullname, username, proj_name, password):
    """Fill in email template with individual user info"""
    with open(template, "r") as f:
        msg = f.read()
    msg = string.replace(msg, "<USER>", fullname)
    msg = string.replace(msg, "<USERNAME>", username)
    msg = string.replace(msg, "<PROJECTNAME>", proj_name)
    msg = string.replace(msg, "<PASSWORD>", password)
    
    return msg

def email_to_file(username, message, mtype):          
    out_file = "{0}_{1}.txt".format(username, mtype)
    filepath = os.path.join(email_path, out_file)
    with open(filepath, 'w') as f:
        f.write(message)
    f.close()
    return filepath

def send_email(fullname, username, email_type, proj_name='None', password='None'):

    if email_type == "new_user":
        template = email_template
    else:
        template = password_template
    
    msg = personalize_msg(template, fullname, username, proj_name, password)

    try:
        email_msg(username, msg, email_type)
    
    except BadEmailRecipient as e:
        # warn user that not everyone got the emails, and save the email text
        # but continue with the script
        print e.message
        print "sendmail reports:\n {0}".format(e.rejected)
        email_to_file(username, msg, email_type)
    except:
        email_to_file(username, msg, email_type)
        raise

def email_msg(receiver, body, email_type):
    
    # This if statement is a temporary hack to divert the password emails
    # so passwords can be delivered via phone.  Make sure Piyanai's email
    # is added to password_to in settings.ini
    if email_type == "new_user":
        #These two lines should remain when hack is removed
        fromaddr = config.get("gmail", "email")
        password = config.get("gmail", "password")    
    else:
        fromaddr = config.get("gmail", "password_to")
        receiver = fromaddr


    msg = MIMEText(body)
    msg['From'] = fromaddr
    msg['To'] = receiver

    server = smtplib.SMTP('127.0.0.1', 25)
    server.ehlo()
    try: 
        server.starttls()
    except smtplib.SMTPException as e:
        if e.message == "STARTTLS extension not supported by server.":
            print ("\n{0}: Sending message failed.\n".format(__file__) +
            "See README for how to enable STARTTLS")  
        raise e

    if email_type == "new_user":   
        msg['Cc'] = config.get("gmail", "cc_list")
        msg['Subject'] = "MOC Welcome mail"
        receivers = [receiver, msg['Cc']]
    else:
        receivers = receiver
        msg['Subject'] = "MOC account password"
    
    rejected = server.sendmail(fromaddr, receivers, msg.as_string())
    # server.sendmail only raises SMTPRecipientsRefused if *all* recipients 
    # fail and the email cannot be sent.
    
    # handle the case where only some recipients fail:
    if len(rejected):
       raise BadEmailRecipient(rejected, msg['Subject'])

if __name__ == "__main__":
    openstack = Openstack(admin_user, admin_pwd, admin_tenant, auth_url, nova_version)

    auth_file = config.get("excelsheet", "auth_file")
    worksheet_key = config.get("excelsheet", "worksheet_key")
    content = parse_spreadsheet.get_details(auth_file, worksheet_key)
    quotas = dict(config.items('quotas'))
    
    for project in content:
        proj_name, proj_id = openstack.create_project(project, "", quotas)

        # email id is used as username as well.....
        for user in content[project]:
            name = user["name"]
            password = random_password(16)
            username = user["email"]
            email = user["email"]
            user_descr = name
            openstack.create_user(name, username, password, user_descr, email, proj_id, proj_name)

    '''
    #TODO: move this code to a 'manual input' function triggered by an option flag
    proj_name = raw_input("Enter the new project name: ")
    proj_descr = raw_input("Enter project description: ")
    username = raw_input("Enter the new username for openstack: ")
    fullname = raw_input("Enter full name: ")
    email = raw_input("Enter user's email address: ")
    user_descr = raw_input("Enter user's description: ")

    proj_id = openstack.create_project(proj_name, proj_descr)

    password = random_password(16)
    openstack.create_user(fullname, username, password, user_descr, email, proj_id, proj_name)

    '''

    print "Done creating accounts."
