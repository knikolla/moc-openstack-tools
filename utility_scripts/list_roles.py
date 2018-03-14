#   Copyright 2017 Massachusetts Open Cloud
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
"""List all roles held by a user or in a project

Script with 2 modes, depending on which of the 2 required, mutually
exclusive options are passed:

    --user <USERNAME>
      List all projects the user belongs to and their role(s) in the project
or
    --project <PROJECT>
      List all users belonging to this project and their roles

Optional flag --config/-c specifies a configuration file; if none specifie,
the script will look for one in /etc/settings.ini and ./settings.ini

Usage:
    python search_ips.py [--user <USERNAME>] [--project <PROJECT>]
                         [-c/--config <CONFIG_FILE>]
"""
import argparse
from six.moves import configparser
from keystoneclient.v3 import client
from keystoneauth1 import session
from keystoneauth1.identity import v3

# This is a hack for now until directory structure is sorted
# When this is removed remember to un-ignore E402 in flake8
import os
import sys
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.abspath(os.path.join(THIS_DIR, os.pardir))
sys.path.insert(0, PROJECT_DIR)
from config import set_config_file

parser = argparse.ArgumentParser(
    description=("List all roles of the specified user in any project, or "
                 "all users of the specified project and their roles."))
parser.add_argument('-c', '--config',
                    help='Specify configuration file.')

mode = parser.add_mutually_exclusive_group(required=True)
mode.add_argument('--user',
                  help='List roles of the specified user.')
mode.add_argument('--project',
                  help=('List all users of the specified project and their'
                        'roles'))

args = parser.parse_args()

CONFIG_FILE = set_config_file(args.config)

config = configparser.ConfigParser()
config.read(CONFIG_FILE)

admin_user = config.get('auth', 'admin_user')
admin_pwd = config.get('auth', 'admin_pwd')
admin_project = config.get('auth', 'admin_project')
auth_url = config.get('auth', 'auth_url')
nova_version = config.get('nova', 'version')

auth = v3.Password(auth_url=auth_url,
                   username=admin_user,
                   user_domain_id='default',
                   password=admin_pwd,
                   project_domain_id='default',
                   project_name=admin_project)
sess = session.Session(auth=auth)

ks = client.Client(session=sess)

if args.user:
    try:
        search = (usr for usr in ks.users.list()
                  if usr.name == args.user).next()
    except StopIteration:
        # FIXME once exceptions are central we can import one for this
        raise Exception('User {} not found.'.format(args.user))

    all_info = [ra for ra in ks.role_assignments.list()
                if ra.user['id'] == search.id]

elif args.project:
    try:
        search = [proj for proj in ks.projects.list()
                  if proj.name == args.project][0]
    except StopIteration:
        # FIXME once exceptions are central we can import one for this
        raise Exception('Project {} not found.'.format(args.project))

    # Remove domain assignments which don't have 'project' under 'scope'
    all_project_roles = [ra for ra in ks.role_assignments.list()
                         if 'project' in ra.scope]
    all_info = [ra for ra in all_project_roles
                if ra.scope['project']['id'] == search.id]

for role_assignment in all_info:
    if args.user:
        info = ks.projects.get(role_assignment.scope['project']['id'])
    if args.project:
        info = ks.users.get(role_assignment.user['id'])
    role = ks.roles.get(role_assignment.role['id'])
    print('{:<20}{}'.format(role.name, info.name))
