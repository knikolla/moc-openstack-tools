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
"""Add new users and projects to OpenStack using Google Sheets data

For each new user definition the script will:
    - Create the user's project if it doesn't exist
    - Modify the project's quotas according to quotas defined in settings.ini
    - Create the user, set their password to a random string
    - Add the user, password, and PIN to the Setpass service
    - Generates a Setpass link the user will visit to reset their password
    - Send a welcome email and a password link email to the new user

Once all users have been processed, the script will:
    - Send a single email subscribing all new users to a mailing list
    - Move the succesfully created users to another worksheet in Google Sheets
    - Print information about any users skipped due to missing/invalid data

For more information on the Setpass service see:
https://github.com/CCI-MOC/setpass

Usage:
    python addusers.py
"""
import re
import sys
import ConfigParser
import argparse
from keystoneclient.v3 import client
from keystoneauth1.identity import v3
from keystoneauth1 import session
from subprocess import Popen, PIPE

# local
import message
import spreadsheet
from moc_utils import get_absolute_path, select_rows
from quotas import QuotaManager
from setpass import SetpassClient, random_password
from config import set_config_file
from moc_exceptions import (InvalidEmailError, ItemExistsError,
                            ItemNotFoundError, NoApprovedRequests)


class User(object):
    """Class for storing user data from the Google Form.
    
    Data from this class will be used to identify an existing OpenStack user
    or create a new one.
    """
    def __init__(self, row, user_name, email=None, first_name=None,
                 last_name=None, is_new=False, is_requestor=True, **kwargs):
        self.name = user_name
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.row = row
        self.is_new = is_new
        self.is_requestor = is_requestor
        self.__dict__.update(kwargs)
       
 
class Project(object):
    """Class for storing project data from the Google Form.
    
    Data from this class will be used to identify an existing OpenStack project
    or create a new one.
    """
    def __init__(self, row, name, contact_name, contact_email, is_new=False,
                 **kwargs):
        self.name = name
        self.contact_name = contact_name
        self.contact_email = contact_email
        self.row = row
        self.is_new = is_new
        self.users = []
        self.__dict__.update(kwargs)


class Openstack:
    def __init__(self, session, nova_version, setpass_url):
        self.keystone = client.Client(session=session)
        self.setpass = SetpassClient(session, setpass_url)
        self.quotas = QuotaManager(session, nova_version)
 
    def create_project(self, project, quotas):
        print "Creating project: {}".format(project.name)
        ks_project = self.keystone.projects.create(
            name=project.name, domain='default',
            description=project.description,
            enabled=True)
        
        # this is unused for now. use project_quotas in the email later
        project_quotas = self.quotas.modify_quotas(ks_project.id,  # noqa: F841
                                                   **quotas)

        # FIXME: don't load config every time
        project_email_cfg = email_defaults.copy()
        project_email_cfg.update(dict(config.items('new_project_email')))

        project_email = message.TemplateMessage(email=project.contact_email,
                                                fullname=project.contact_name,
                                                project=ks_project.name,
                                                **project_email_cfg)
 
        try:
            project_email.send()
        except:
            path = config.get('output', 'email_path')
            project_email.dump_to_file(target_path=path, label="new_project")
            raise

        return ks_project

    def create_user(self, user, project):
        """Create a new OpenStack user from an addusers.User
        
        This function assumes you have already verfied the user doesn't exist.
        """
        print "Creating user {}".format(user.name)
        password = random_password(16)
        fullname = "{} {}".format(user.first_name, user.last_name)
        ks_user = self.keystone.users.create(name=user.name,
                                             email=user.email,
                                             password=password,
                                             domain='default',
                                             description=fullname)
        
        setpass_token = self.setpass.get_token(ks_user.id, password, user.pin)
        password_url = self.setpass.get_url(setpass_token)

        usr_cfg = email_defaults.copy()
        usr_cfg.update(dict(config.items('welcome_email')))
        welcome_email = message.TemplateMessage(email=ks_user.email,
                                                username=ks_user.name,
                                                fullname=fullname,
                                                project=project.name,
                                                **usr_cfg)
        pwd_cfg = email_defaults.copy()
        pwd_cfg.update(dict(config.items('password_email')))
        password_email = message.TemplateMessage(
            email=ks_user.email, fullname=fullname,
            setpass_token_url=password_url, **pwd_cfg)
        
        try:
            welcome_email.send()
            password_email.send()
        except:
            # Save both emails if either throws an error, just in case
            path = config.get('output', 'email_path')
            welcome_email.dump_to_file(target_path=path, label="welcome")
            password_email.dump_to_file(target_path=path, label="password")
            raise
        
        return ks_user

    def grant_role(self, auth_url, project_id, user_id, role_id):
        """Grants the user the specified role on the project."""
        url = '{}/projects/{}/users/{}/roles/{}'.format(auth_url,
                                                        project_id,
                                                        user_id, role_id)
        return self.keystone.session.put(url)


# NOTE: This function is not currently used,
# but keep it for the future when we move away from Google Forms.
# It should be moved to a utilities module.
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


def exists_in_keystone(check_thing, keystone_things):
    """Check for user or project name conflicts.

    new_thing should be an addusers.User or addusers.Project
    keystone_things should be a list of Keystone user or project resources
    """
    matches = (thing for thing in keystone_things if thing.name.lower() ==
               check_thing.name.lower())

    try:
        return matches.next()
    except StopIteration:
        return None


def parse_rows(rows, select_user=None):
    """Parse spreadsheet user/project data into User and Project classes
    
    Expects 'rows' to include all rows, with row 0 being the header row
    Returns a dictionary of projects keyed by project name, and a list
    of rows that were not blank but failed to parse correctly.

    Select_user allows caller to handle requests from one user only.
    """
    # Column index in the Google Sheet for username
    # This may need to be updated if question order on the form is changed
    USER_COLUMN = 4

    projects = {}
    bad_rows = []

    if select_user:
        try:
            rows = select_rows(select_user, USER_COLUMN, rows)
        except ValueError as ve:
            raise argparse.ArgumentError(None, ve.message)
    else:
        rows = enumerate(rows)

    for idx, entry in rows:
        # ignore row 0 (the header row) and blank rows
        if (idx == 0) or (entry == []):
            continue
        elif (entry[0].lower().strip() != 'approved') or (entry[1] == ''):
            # Don't process requests that haven't gone through the
            # approval/notification process yet
            # entry[0] is Approved
            # entry[1] is Helpdesk Notified
            # entry[2] is Reminder sent
            # entry[3] is Timestamp
            bad_rows.append((idx, ("Approval/Notification "
                                   "Incomplete: {}").format(entry[4])))
            continue
        try:
            email = entry[4].replace(u'\xa0', ' ').strip()
            user_info = {'user_name': email,
                         'email': email,
                         'first_name': entry[5],
                         'last_name': entry[6]}

            if entry[7] == 'No':
                user_info.update({'is_new': True,
                                  'org': entry[8],
                                  'role': entry[9],
                                  'phone': entry[10],
                                  'sponsor': entry[11],
                                  'pin': entry[12],
                                  'comment': entry[13]})
                # entry[14] asks whether a new or existing
                # project = only used for form navigation
                # FIXME: add option to choose "no project"
                # for teams who sign up for a new project
                # together?
            
            user = User(row=idx, **user_info)
            
            if entry[15] == "":
                # the user chose to join an existing project
                # info in entry[18] to entry[20]
                project_name = entry[18]
                if project_name not in projects:
                    project = Project(row=idx,
                                      name=project_name,
                                      contact_name=entry[19],
                                      contact_email=entry[20])
                    projects[project.name] = project
                 
                projects[project_name].users.append(user)
            
            elif entry[15] in projects:
                # FIXME:
                # This should probably raise an error of some sort.  It
                # covers 2 weird edge cases, either:
                #   a) the project exists, another user from this batch
                #      asked to be added to it
                #   b) project doesn't exist, but another user from this
                #      batch requested a new project with this name.
                # For now, while we get stuff working, just assume they are
                # the same project.
                projects[entry[15]].users.append(user)

            else:
                # a new project was requested - info in entry[15] to entry[17]
                project = Project(
                    row=idx, name=entry[15],
                    contact_name=user.first_name + " " + user.last_name,
                    contact_email=user.email,
                    description=entry[16],
                    is_new=True)
                project.users.append(user)

                try:
                    for add_user in entry[17].split(','):
                        add_user = add_user.strip()
                        existing_user = User(row=idx, user_name=add_user,
                                             email=add_user,
                                             is_requestor=False)
                        project.users.append(existing_user)
                except IndexError:
                    # entry[17] is the last possible filled cell in a new
                    # project entry, so if it was left blank it's not there
                    # FIXME by changing field order on the forms?
                    pass
                except:
                    # If the user typed something in this box but didn't
                    # follow instructions
                    print ("WARNING: cannot add additional users to "
                           "project `{}` from input: `{}`").format(
                               entry[15], entry[17])

                projects[project.name] = project
        except IndexError:
            # Somehow a required field is blank
            bad_rows.append((idx, "Missing Required Field"))
    
    if not projects:
        raise NoApprovedRequests(row_filter=select_user)

    return projects, bad_rows


def mailman_subscribe(email_list, mailman_config):
    "Subscribe each address in email_list to the Mailman mailing list"

    subscriber_list = "\n".join(email_list)
  
    ssh_command = ("ssh -l {mailman_user} {mailman_server} "
                   "{subscribe_command}").format(**mailman_config)

    subp = Popen(ssh_command.split(), stdin=PIPE, stderr=PIPE)
    subp.communicate(input=subscriber_list)[0]


if __name__ == "__main__":
    
    help_description = ("Add new users and projects to OpenStack using "
                        "data from Google Sheets.")
    parser = argparse.ArgumentParser(description=help_description)
    parser.add_argument('-c', '--config',
                        help='Specify configuration file.')
    parser.add_argument('--debug', action='store_true',
                        help='Print additional debugging output.')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--user',
                      help='Process requests for a single user.')
    # The value of all_reqs is never used, its purpose is to require the caller
    # to explicitly declare that they wish to process all rows
    mode.add_argument('--all', dest='all_reqs', action='store_true',
                      help='Process all available requests.')

    args = parser.parse_args()

    CONFIG_FILE = set_config_file(args.config)

    config = ConfigParser.ConfigParser()
    config.read(CONFIG_FILE)

    admin_user = config.get('auth', 'admin_user')
    admin_pwd = config.get('auth', 'admin_pwd')
    admin_project = config.get('auth', 'admin_project')
    auth_url = config.get('auth', 'auth_url')
    nova_version = config.get('nova', 'version')

    setpass_url = config.get('setpass', 'setpass_url')
    auth = v3.Password(auth_url=auth_url,
                       username=admin_user,
                       user_domain_id='default',
                       password=admin_pwd,
                       project_domain_id='default',
                       project_name=admin_project)
    session = session.Session(auth=auth)
    
    openstack = Openstack(session=session, nova_version=nova_version,
                          setpass_url=setpass_url)
    auth_file = get_absolute_path(config.get("excelsheet",
                                             "auth_file"))
    worksheet_key = config.get("excelsheet", "worksheet_key")
    quotas = dict(config.items('quotas'))
    email_defaults = dict(config.items('email_defaults'))
    
    sheet = spreadsheet.Spreadsheet(auth_file, worksheet_key)
    rows = sheet.get_all_rows("Form Responses 1")

    try:
        content, bad_rows = parse_rows(rows, select_user=args.user)
    except NoApprovedRequests as e:
        print e.message
        sys.exit(1)
 
    copy_index = []
    subscribe_emails = []

    # Get these once at the beginning and update them as we add users and
    # projects with the script
    ks_users = openstack.keystone.users.list()
    ks_projects = openstack.keystone.projects.list()
    ks_member_role = openstack.keystone.roles.find(name='_member_')
    
    for project in content:
        # what we get back here is a keystone project, or None
        ks_project = exists_in_keystone(content[project], ks_projects)
        try:
            if content[project].is_new:
                    if ks_project:
                        raise ItemExistsError('Project', content[project].name)
                    ks_project = openstack.create_project(content[project],
                                                          quotas)
            elif not ks_project:
                # this could happen if we delete a project or change its name
                # but forget to update the form
                raise ItemNotFoundError('Project', content[project].name)
        except (ItemExistsError, ItemNotFoundError) as e:
            # FIXME:  Need to some way to handle users associated with the
            # skipped project
            # FIXME: Our form doesn't have a way to inform the user they
            # chose a project name that is already in use.  Can we do that?
            bad_rows.append((content[project].row, e.message))
            continue
              
        # email id is used as username as well.....
        for user in content[project].users:
            ks_user = exists_in_keystone(user, ks_users)
            try:
                if user.is_new:
                    if ks_user:
                        raise ItemExistsError('User', user.name)
                    new_ks_user = openstack.create_user(user, ks_project)
                    openstack.grant_role(auth_url, ks_project.id,
                                         new_ks_user.id, ks_member_role.id)
                    ks_users.append(new_ks_user)
                    subscribe_emails.append(user.email)
                elif not ks_user:
                    if user.is_requestor:
                        raise ItemNotFoundError('User', user.name)
                    else:
                        # We don't treat this as a critical error
                        print ("WARNING: Additional user `{}` does not exist "
                               "in Keystone. The user will not be added to "
                               "project {}").format(user.name,
                                                    ks_project.name)
                
                else:
                    print ("Adding existing user {} to "
                           "project {}").format(ks_user.name, ks_project.name)
                    response = openstack.grant_role(auth_url, ks_project.id,
                                                    ks_user.id,
                                                    ks_member_role.id)
                
                if user.is_requestor:
                    copy_index.append(user.row)
                
            except message.BadEmailRecipient as err:
                # Warn that not everyone got the email, but don't
                # otherwise treat this as a failure
                print err.message
                print "sendmail reports: \n {0}".format(err.rejected)
            except (ItemExistsError,
                    InvalidEmailError, ItemNotFoundError) as e:
                bad_rows.append((user.row, e.message))
                    
    if subscribe_emails:
        mailman_config = dict(config.items('mailman'))
        mailman_subscribe(subscribe_emails, mailman_config)

    # Copy and delete only the successful rows
    if copy_index:
        if args.user and (len(copy_index) > 1):
            print ("WARNING: {} approved requests were processed for user {}. "
                   "You may need to close multiple tickets.").format(
                       len(copy_index), args.user)
        copy_rows = [r for r in rows if rows.index(r) in copy_index]
        sheet.append_rows(copy_rows, target="Current Users")
        result = sheet.delete_rows(copy_index, 'Form Responses 1')
    elif args.debug:
        print "WARNING: No rows were successfully processed."
   
    if not args.debug:
        # This error should only display in debugging mode
        bad_rows = [(idx, msg) for (idx, msg) in bad_rows
                    if "Approval/Notification Incomplete" not in msg]
 
    if bad_rows:
        ERROR_FORMAT = "{row:>16}    {error}"
        print "The following rows were not fully processed due to errors:"
        print ERROR_FORMAT.format(row="ROW", error="ERROR")
        print ERROR_FORMAT.format(row="-----", error="-----")
        for (row, error_msg) in bad_rows:
            # In the Google Sheets web GUI, row 0 is numbered 1
            print ERROR_FORMAT.format(row=(row + 1), error=error_msg)
    
    '''
    # TODO: move this code to a 'manual input' function
    # triggered by an option flag
    proj_name = raw_input("Enter the new project name: ")
    proj_descr = raw_input("Enter project description: ")
    username = raw_input("Enter the new username for openstack: ")
    fullname = raw_input("Enter full name: ")
    email = raw_input("Enter user's email address: ")
    user_descr = raw_input("Enter user's description: ")
    proj_id = openstack.create_project(proj_name, proj_descr)
    password = random_password(16)
    openstack.create_user(fullname, username, password, user_descr, email,
                          proj_id, proj_name)
    '''

    print "Done creating accounts."
