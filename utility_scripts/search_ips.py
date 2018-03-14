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
"""Search for a public IP by address

Utility script for finding information about a public IP.

Usage:
    python search_ips.py <IP> [--router] [--floatingip]

Optional flags --router and --floatingip are mutually exclusive, and will
limit the search range to only that type of IP.
"""
import argparse
from six.moves import configparser
from keystoneclient.v3 import client
from neutronclient.v2_0 import client as nclient
from neutronclient.common.exceptions import NotFound as NeutronNotFound
from novaclient import client as novaclient
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


def get_router_ip(router):
    """Returns the external IP of the given router if it has one, or None"""
    ext_gateway = router['external_gateway_info']
    if ext_gateway:
        router_ip = ext_gateway['external_fixed_ips'][0]['ip_address']
        return router_ip


def floating_ip_search(ip_addr, client):
    """Returns the matching floating IP, or False if none found."""
    try:
        found_ip = (ip for ip in client.list_floatingips()['floatingips']
                    if ip['floating_ip_address'] == ip_addr).next()
    except StopIteration:
        print("{} is not a floating IP".format(ip_addr))
        return False
    return found_ip


def router_search(ip_addr, client):
    """Returns a router with this external IP, or False if none found."""
    try:
        found_router = (r for r in neutron.list_routers()['routers']
                        if get_router_ip(r) == ip_addr).next()
    except StopIteration:
        print("{} is not a router IP".format(ip_addr))
        return False
    return found_router


def print_report(**report_info):
    """Print information to the screen"""
    FORMAT_STR = ("Type: {ip_type}\nid: {ip_id}\n"
                  "owned by project:\n"
                  "\tid: {project_id}\n\tname: {project_name}\n"
                  "attached to device:\n"
                  "\tid: {device_id}\n\tname: {device_name}")
    print(FORMAT_STR.format(**report_info))


# Arguments
parser = argparse.ArgumentParser(
    description="Find info about a particular floating IP")
parser.add_argument('-c', '--config',
                    help='Specify configuration file.')
mode = parser.add_mutually_exclusive_group(required=False)
mode.add_argument('--floatingip', action='store_true',
                  help='Only search for floating IPs')
mode.add_argument('--router', action='store_true',
                  help='Only search for routers')
parser.add_argument('ip', help="the public IP to search for")

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
neutron = nclient.Client(session=sess)

ip_info = dict()
found_ip = None

if not args.router:
    # if the user didn't specify to search only routers
    found_ip = floating_ip_search(args.ip, neutron)
    if found_ip:
        ip_info.update({'ip_type': 'floating ip',
                        'ip_id': found_ip['id'],
                        'ip_addr': found_ip['floating_ip_address']})
        try:
            port = neutron.show_port(found_ip['port_id'])
            server_id = port['port']['device_id']
            nova = novaclient.Client(nova_version, session=sess)
            server = nova.servers.get(server_id)
            ip_info.update({'device_id': server.id,
                            'device_name': server.name})
        except NeutronNotFound:
            ip_info.update({'device_id': None,
                            'device_name': None})

if not args.floatingip and not found_ip:
    # if user didn't specify to search only floating IPs,
    # and the given IP is not already found
    found_ip = router_search(args.ip, neutron)
    if found_ip:
        ip_info.update({'ip_type': 'router',
                        'ip_id': None,
                        'ip_addr': get_router_ip(found_ip),
                        'device_id': found_ip['id'],
                        'device_name': found_ip['name']})

if found_ip:
    ks = client.Client(session=sess)
    project = ks.projects.get(found_ip['tenant_id'])
    ip_info.update({'project_id': project.id,
                   'project_name': project.name})

    print_report(**ip_info)
