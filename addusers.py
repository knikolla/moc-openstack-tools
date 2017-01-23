__author__ = 'rahuls@ccs.neu.edu, kamfonik@bu.edu'

import json
import string
import random
import re
import ConfigParser
from keystoneclient.v2_0 import client
from novaclient import client as novaclient
from neutronclient.v2_0 import client as neutronclient
from cinderclient.v2 import client as cinderclient

#setpass
from keystoneauth1.identity import v3
from keystoneauth1 import session

#local
import message
import spreadsheet

CONFIG_FILE = "settings.ini"

config = ConfigParser.ConfigParser()
config.read(CONFIG_FILE)

admin_user = config.get('auth', 'admin_user')
admin_pwd = config.get('auth', 'admin_pwd')
admin_tenant = config.get('auth', 'admin_tenant')
auth_url = config.get('auth', 'auth_url')
region_name = config.get('auth', 'region_name') # not needed in Mitaka
nova_version = config.get('nova', 'version')

keystone_v3_url = config.get('setpass', 'keystone_v3_url')
setpass_url = config.get('setpass', 'setpass_url')

class InvalidEmailError(Exception):
    """User's email address does not pass basic format validation"""

class UserExistsError(Exception):
    """User already exists and cannot be created"""

def random_password(size):
    chars = string.ascii_letters + string.digits + string.punctuation[2:6]
    return ''.join(random.choice(chars) for _ in range(size))

class Setpass:
    def __init__(self, keystone_v3_url, keystone_admin, keystone_password, setpass_url):
        self.url = setpass_url
        auth = v3.Password(auth_url=keystone_v3_url,
                           username=keystone_admin,
                           user_domain_id = 'default',
                           password=keystone_password)
        self.session = session.Session(auth=auth)
    
    def get_token(self, userid, password, pin):
        """ Add the user ID and random password to the setpass database.  
        
        Returns a token allowing the user to set their password.
        """
        body = { 'password': password, 'pin': pin }
        request_url = '{base}/token/{userid}'.format(base=self.url, userid=userid)
        response = self.session.put(request_url, json=body)
        token = response.text
        return token

    def get_url(self, token):
        """ Generate URL for the user to set their password """
        url = "{base}?token={token}".format(base=self.url, token=token)
        return url

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
   
        self.setpass = Setpass(keystone_v3_url, uname, password, setpass_url) 
    
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

    def create_user(self, fullname, username, password, description, email, tenant_id, proj_name, pin):
        users = [user.name for user in self.keystone.users.list()]
        if username not in users:
            print "\tUSER: %-30s    PRESENT: NO, CREATING IT" % username
            user = self.keystone.users.create(name=username,
                                              email=email,
                                              password=password,
                                              tenant_id=tenant_id)
            
            setpass_token = self.setpass.get_token(user.id, password, pin)
            password_url = self.setpass.get_url(setpass_token)

            usr_cfg = dict(config.items('welcome_email'))
            pwd_cfg = dict(config.items('password_email'))

            welcome_email = message.TemplateMessage(email=email, username=username, fullname=fullname, project=project, **usr_cfg)
            password_email = message.TemplateMessage(email=email, fullname=fullname, setpass_token_url=password_url, **pwd_cfg)
            try:
                welcome_email.send()
                password_email.send()
            except:
                # Save both emails if either throws an error, just in case
                path = config.get('output', 'email_path')
                welcome_email.dump_to_file(target_path=path, label="welcome")
                password_email.dump_to_file(target_path=path, label="password")
                raise
        else:
            print "\tUSER: %-30s    PRESENT: YES" % username
            raise UserExistsError("User exists: {0}.".format(username))

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

def validate_email(uname):
    """Check that the email address provided matches a few simple rules

    The email address should have no whitespace, exactly 1 '@' symbol, and
    at least one '.' following the @ symbol. 
    """
    pattern = re.compile('[^@\s]+@[^@\s]+\.[^@\s]+')
    if pattern.match(uname):
        return
    else:
        raise InvalidEmailError('Not a valid email address: {}'.format(uname))

def parse_rows(rows):
    """Parse new user data from the spreadsheet into a dictionary
    
    Expects 'rows' to include all rows, with row 0 being the header row
    Returns a dictionary of projects/users and a list of rows that were
    incomplete but not blank.
    """
    projects = {}    
    bad_rows = []
    for idx, entry in enumerate(rows):
        #ignore row 0 (the header row) and blank rows
        if (idx == 0) or (entry == []):
            continue
        elif (len(entry) < 10) or ('' in entry):
            bad_rows.append(idx)
        else:
            project = entry[1]
            name = entry[2] + " " + entry[3]
            email = entry[4].replace(u'\xa0', ' ').strip()
            pin = entry[10]
            req = {"name": name, "email": email, "pin": pin, "row": idx }

            if project in projects:
                projects[project].append(req)
            else:
                projects[project] = [req]
    return projects, bad_rows

if __name__ == "__main__":
    openstack = Openstack(admin_user, admin_pwd, admin_tenant, auth_url, nova_version)
    auth_file = config.get("excelsheet", "auth_file")
    worksheet_key = config.get("excelsheet", "worksheet_key")
    quotas = dict(config.items('quotas'))
    
    sheet = spreadsheet.Spreadsheet(auth_file, worksheet_key)
    rows = sheet.get_all_rows("Form Responses 1")
    content, bad_rows = parse_rows(rows)
    
    failed_create = []
    copy_index = []
    subscribe_emails = []
    
    for project in content:
        proj_name, proj_id = openstack.create_project(project, "", quotas)

        # email id is used as username as well.....
        for user in content[project]:
            name = user["name"]
            password = random_password(16)
            email = user["email"]
            username = email
            pin = user["pin"]
            user_descr = name
            try: 
                validate_email(email)
                openstack.create_user(name, username, password, 
                        user_descr, email, proj_id, proj_name, pin) 
                copy_index.append(user['row'])
                subscribe_emails.append(email)                
            except message.BadEmailRecipient as err:
                # Warn the user that not everyone got the email, but don't
                # otherwise treat this as a failure
                print err.message
                print "sendmail reports: \n {0}".format(err.rejected)
            except (UserExistsError, InvalidEmailError) as e:
                user['error'] = e.message
                failed_create.append(user)

    if subscribe_emails:
        list_cfg = dict(config.items('listserv'))
        listserv = message.ListservMessage(subscribe_emails, **list_cfg)
        listserv.send()

    # Copy and delete only the successful rows
    if copy_index:
        copy_rows = [r for r in rows if rows.index(r) in copy_index] 
        sheet.append_rows(copy_rows, target="Current Users")
        result = sheet.delete_rows(copy_index, 'Form Responses 1')
    else:
        print "WARNING: No spreadsheet rows were copied."
    
    # In the web GUI, row 0 is numbered 1
    GUI_rows = [(x+1) for x in bad_rows]
    print ("WARNING: {count} rows ignored due to missing information: " +
          "{rowlist}\n").format(count=len(bad_rows), rowlist=GUI_rows)
 
    if failed_create:
        ERROR_FORMAT="\t{name:>25}\t{error}"
        print "The following users were not created due to errors:"
        print ERROR_FORMAT.format(name="NAME", error="ERROR")
        print ERROR_FORMAT.format(name="-----", error="-----")
        for user in failed_create:
            print ERROR_FORMAT.format(**user)
        
    
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
