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
"""Update a project's OpenStack quotas using Google Sheets data

For each entry in the Google Sheet, the script will:
    - update the specified quotas
    - generate an email describing the update
    - send the email to the requestor, cc'ing all project users and anyone
      else specified in the config file cc_list parameter

Usage:
    python set-quotas.py
"""
import argparse
import ConfigParser
import sys
from keystoneclient.v3 import client
from keystoneauth1.identity import v3
from keystoneauth1 import session

from config import set_config_file
from moc_utils import get_absolute_path, select_rows
from quotas import QuotaManager
from message import TemplateMessage
import spreadsheet
from moc_exceptions import ItemNotFoundError, NoApprovedRequests


def parse_rows(rows, select_project=None):
    """Parse quota update data from the spreadsheet into a dictionary
    
    Expects 'rows' to include all rows, with row 0 being the header row
    Returns a dictionary of projects/quotas.
    """
    # NOTE: entry[17] is a required field in the Google Form, so it is safe
    # to assume entry[0:16] exists.
    
    # Column index in the Google Sheet for project name
    # This may need to be updated if question order on the form is changed
    PROJECT_COLUMN = 8
    
    project_list = []

    if select_project:
        try:
            rows = select_rows(select_project, PROJECT_COLUMN, rows)
            if len(rows) > 2:
                print ("WARNING: Multiple requests found for project {}. All "
                       "{} requests will be processed. You may need to close "
                       "multiple tickets.").format(args.project, len(rows) - 1)
        except ValueError as ve:
            raise argparse.ArgumentError(None, ve.message)
    else:
        rows = enumerate(rows)

    for idx, entry in rows:
        # ignore row 0 (the header row) and blank rows
        if (idx == 0) or (entry == []):
            continue
        # skip rows that have not been through approval/notification
        elif (entry[0].lower().strip() != 'approved') or (entry[1] == ''):
            # entry[0] is Approved
            # entry[1] is Helpdesk Notified
            continue
        else:
            project = dict()
            # entry [2] is Reminder Sent
            # entry [3] is Timestamp
            project['email'] = entry[4].replace(u'\xa0', ' ').strip()
            project['user_fullname'] = entry[5] + ' ' + entry[6]
            # entry[7] is organization
            project['name'] = entry[8]
            # entry[9] is Type of Increase
            # entry[10] is End Date
            quotas = {'instances': entry[11],
                      'cores': entry[12],
                      'ram': entry[13],
                      'floatingip': entry[14],
                      'network': entry[15],
                      'port': entry[16],
                      'volumes': entry[17],
                      'snapshots': entry[18],
                      'gigabytes': entry[19]}
            
            unchanged_quotas = [q for q in quotas if quotas[q] == '']
            for quota_name in unchanged_quotas:
                    del quotas[quota_name]

            for quota_name, value in quotas.iteritems():
                quotas[quota_name] = int(value)

            # OpenStack wants the RAM quota in MB, but the form requests it in
            # GB so the users aren't confused by multiplying by 1000 vs. 1024
            if 'ram' in quotas:
                quotas['ram'] = quotas['ram'] * 1024

            project['quotas'] = quotas

            # entry[20] is Comments - required field
            # entry[21] is MOC Notes - not required
            
            project['row'] = idx

            project_list.append(project)

    if not project_list:
        raise NoApprovedRequests(row_filter=select_project)

    return project_list


def build_quota_table(old_quotas, updated_quotas):
    """Construct the table of updated quotas for insertion into the email"""
      
    QUOTA_FORMAT = "{quota:>25} |{old_value:>10} |{new_value:>10}"
    
    headers = QUOTA_FORMAT.format(quota='QUOTA  ', old_value='OLD VALUE',
                                  new_value='NEW VALUE')
    dividers = QUOTA_FORMAT.format(quota='-' * 20, old_value='-' * 10,
                                   new_value='-' * 10)
    
    quota_rows = [headers, dividers]
    for q in updated_quotas:
        quota_rows.append(QUOTA_FORMAT.format(quota=q,
                                              old_value=old_quotas[q],
                                              new_value=updated_quotas[q]))
    
    quota_table = "\n".join(quota_rows)
    return quota_table


def match_keystone_project(all_ks_projects, form_project):
    """Match the project specified by the user to a keystone project"""
    ks_project = [project for project in all_ks_projects
                  if form_project.lower() == project.name.lower()]
    
    if not ks_project:
        raise ItemNotFoundError('project', form_project)
    else:
        return ks_project[0]


if __name__ == "__main__":

    help_description = ("Update OpenStack project quotas using data from "
                        "Google Sheets.")
    parser = argparse.ArgumentParser(description=help_description)
    parser.add_argument('-c', '--config',
                        help='Specify configuration file.')
    parser.add_argument('--debug', action='store_true',
                        help='Print additional debugging output.')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--project',
                      help='Process requests from a single project.')
    # The value of all_reqs is never used, its purpose is to require the caller
    # to explicitly declare that they wish to process all rows
    mode.add_argument('--all', dest='all_reqs', action='store_true',
                      help='Process all available requests.')

    args = parser.parse_args()
   
    if args.config is not None:
        CONFIG_FILE = set_config_file(args.config)
    else:
        CONFIG_FILE = set_config_file()

    # configuration
    config = ConfigParser.ConfigParser()
    config.read(CONFIG_FILE)
    admin_user = config.get('auth', 'admin_user')
    admin_pwd = config.get('auth', 'admin_pwd')
    admin_project = config.get('auth', 'admin_project')
    auth_url = config.get('auth', 'auth_url')
    nova_version = config.get('nova', 'version')
    quota_auth_file = get_absolute_path(config.get('quota_sheet', 'auth_file'))
    quota_worksheet_key = config.get('quota_sheet', 'worksheet_key')
    quota_template = config.get('quota_email', 'template')

    # openstack auth
    auth = v3.Password(auth_url=auth_url,
                       username=admin_user,
                       user_domain_id='default',
                       project_name=admin_project,
                       project_domain_id='default',
                       password=admin_pwd)
    session = session.Session(auth=auth)
    keystone = client.Client(session=session)
    all_ks_projects = keystone.projects.list()
    quota_manager = QuotaManager(session=session, nova_version=nova_version)
    
    # get data from Google Sheet
    sheet = spreadsheet.Spreadsheet(quota_auth_file, quota_worksheet_key)
    rows = sheet.get_all_rows("Form Responses 1")
    
    try:
        project_list = parse_rows(rows, select_project=args.project)
    except NoApprovedRequests as e:
        print e.message
        sys.exit(1)

    bad_rows = []
    copy_index = []

    # NOTE: 'project' is the project data from Google Sheets
    # and 'ks_project' is the matching project resource from Keystone
    for project in project_list:
        try:
            ks_project = match_keystone_project(all_ks_projects,
                                                project['name'])
        except ItemNotFoundError as err:
            print err.message
            bad_rows.append(project['row'])
            continue
        
        old_quotas = quota_manager.get_current(ks_project.id)

        print "updating the following quotas for project {}:\n\t{}".format(
              ks_project.name, project['quotas'].keys())
        
        new_quotas = quota_manager.modify_quotas(ks_project.id,
                                                 **project['quotas'])
        quota_cfg = dict(config.items('email_defaults'))
        quota_cfg.update(dict(config.items('quota_email')))
        quota_cfg['subject'] = quota_cfg['subject'].format(
            project=ks_project.name)
        
        # add the emails of the project's other users to the CC list
        roles = keystone.role_assignments.list(project=ks_project.id)
        for role in roles:
            user = keystone.users.get(role.user['id'])
            try:
                if user.email != project['email']:
                    quota_cfg['cc_list'] = ", ".join([quota_cfg['cc_list'],
                                                      user.email])
            except AttributeError:
                # some service users etc. might not have an email
                pass

        quota_list = build_quota_table(old_quotas, project['quotas'])
        msg = TemplateMessage(email=project['email'],
                              fullname=project['user_fullname'],
                              project=ks_project.name,
                              quota_list=quota_list,
                              **quota_cfg)
        msg.send()
        copy_index.append(project['row'])
        print "Successfully updated quotas for project {}".format(
              ks_project.name)

    # FIXME: code is duplicated from addusers.py, centralize it
    if copy_index:
        copy_rows = [r for r in rows if rows.index(r) in copy_index]
        sheet.append_rows(copy_rows, target="Processed Requests")
        result = sheet.delete_rows(copy_index, 'Form Responses 1')
    elif args.debug:
        print "WARNING: No spreadsheet rows were copied."
    
    if bad_rows and args.debug:
        print "WARNING: The following rows were not processed: {}".format(
              bad_rows)
