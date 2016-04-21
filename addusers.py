__author__ = 'rahuls@ccs.neu.edu'

import os
import json
import string
import random
import ConfigParser
from keystoneclient.v2_0 import client
from novaclient import client as novaclient

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

nova_version = config.get('nova', 'version')

email_template = config.get('templates', 'email_template')
password_template = config.get('templates', 'password_template')

email_path = config.get('output', 'email_path')
password_path = config.get('output', 'password_path')


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

    def create_project(self, name, description):
        tenants = [tenant.name for tenant in self.keystone.tenants.list()]
        if name not in tenants:
            print "TENANT: %-30s   \tPRESENT: NO, CREATING IT" % name
            tenant = self.keystone.tenants.create(tenant_name=name,
                                                  description=description,
                                                  enabled=True)
            return tenant.id
        else:
            print "TENANT: %-30s   \tPRESENT: YES" % name
            tenants = [(tenant.name, tenant.id) for tenant in self.keystone.tenants.list()]
            for tenant in tenants:
                if name == tenant[0]:
                    return tenant[1]

    def create_user(self, name, username, password, description, email, tenant_id, proj_name):
        users = [user.name for user in self.keystone.users.list()]
        if username not in users:
            print "\tUSER: %-30s    PRESENT: NO, CREATING IT" % username
            user = self.keystone.users.create(name=username,
                                              email=email,
                                              password=password,
                                              tenant_id=tenant_id)

            send_email(name, username, proj_name, password)

        else:
            print "\tUSER: %-30s    PRESENT: YES" % username

    def modify_quotas(self, tenant_id, **kwargs):
        """
        modify default quota values for the given tenant.
        kwargs can be cores, fixed_ips, floating_ips, injected_file_content_bytes,
        injected_file_path_bytes, injected_files, instances, key_pairs, metadata_items,
        ram, security_group_rules, security_groups, server_group_members, server_groups
        """
        new_quota = self.nova.quotas.update(tenant_id, **kwargs)
        print "New quota values are: ", new_quota


def send_email(fullname, username, proj_name, password):
    with open(email_template, "r") as f:
        msg = f.read()
    msg = string.replace(msg, "<USER>", fullname)
    msg = string.replace(msg, "<USERNAME>", username)
    msg = string.replace(msg, "<PROJECTNAME>", proj_name)

    # send welcome email
    email_msg(username, msg, "new_user")

    with open(password_template, "r") as f:
        msg = f.read()
    msg = string.replace(msg, "<USER>", fullname)
    msg = string.replace(msg, "<USERNAME>", username)
    msg = string.replace(msg, "<PASSWORD>", password)

    # send password email
    email_msg(username, msg, "password")


def email_msg(receiver, body, type):
    fromaddr = config.get("gmail", "email")
    password = config.get("gmail", "password")

    msg = MIMEText(body)
    msg['From'] = fromaddr
    msg['To'] = receiver

    server = smtplib.SMTP('127.0.0.1', 25)
    server.ehlo()
    server.starttls()
    #server.login(fromaddr, password)

    if type == "new_user":
        msg['Cc'] = config.get("gmail", "cc_list")
        msg['Subject'] = "MOC Welcome mail"
        receivers = [receiver, msg['Cc']]
        server.sendmail(fromaddr, receivers, msg.as_string())
    else:
        msg['Subject'] = "MOC account password"
        server.sendmail(fromaddr, receiver, msg.as_string())



if __name__ == "__main__":
    openstack = Openstack(admin_user, admin_pwd, admin_tenant, auth_url, nova_version)

    auth_file = config.get("excelsheet", "auth_file")
    worksheet_key = config.get("excelsheet", "worksheet_key")
    content = parse_spreadsheet.get_details(auth_file, worksheet_key)

    for project in content:
        proj_id = openstack.create_project(project, "")

        # email id is used as username as well.....
        for user in content[project]:
            name = user["name"]
            password = random_password(16)
            username = user["email"]
            email = user["email"]
            user_descr = name
            openstack.create_user(name, username, password, user_descr, email, proj_id, project)

    '''
    proj_name = raw_input("Enter the new project name: ")
    proj_descr = raw_input("Enter project description: ")
    username = raw_input("Enter the new username for openstack: ")
    fullname = raw_input("Enter full name: ")
    email = raw_input("Enter user's email address: ")
    user_descr = raw_input("Enter user's description: ")

    proj_id = openstack.create_project(proj_name, proj_descr)

    password = random_password(16)
    openstack.create_user(fullname, username, password, user_descr, email, proj_id, proj_name)

    # TODO: modify quotas doesn't work. Need to fix this
    openstack.modify_quotas(proj_id,
                            security_groups=-1,
                            security_group_rules=-1,
                            floating_ips=5)
    '''

    print "Done creating accounts."
