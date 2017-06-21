# Copyright 2017 Massachusetts Open Cloud
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
"""Audits quota requests

Utility script for finding projects that don't match quota requests.

Optional second flag which specifies path to configuration file. If specified,
configuration file will be used for authentication. If none specified, the
script will use environment variables.

Usage:
    python quota_audit.py [<REQUEST FILE>] [<CONFIG_FILE>]
"""
import os
import csv
import argparse
import ConfigParser
from keystoneclient.v3 import client
from keystoneauth1 import session
from keystoneauth1.identity import v2
from keystoneauth1.exceptions.http import NotFound
from neutronclient.v2_0 import client as nclient
from novaclient import client as novaclient
from cinderclient.v2 import client as cinderclient


def diff_moc_quotas(project_quotas):
    different_quotas = {}
    for resource in MOC_STANDARDS:
        if MOC_STANDARDS[resource] == project_quotas[resource]:
            continue
        else:
            different_quotas[resource] = project_quotas[resource]
    return different_quotas


def to_single_dict(nova_q, cinder_q, neutron_q):
    combined = {}
    combined.update(nova_q)
    combined.update(cinder_q)
    combined.update(neutron_q)
    return combined


def proj_to_request_dict(project_name):
    request_dict = {}
    for row in READER:
        if row['OpenStack project name'] == project_name:
            request_dict['instances'] = row['Instances']
            request_dict['cores'] = row['VCPUs']
            request_dict['ram'] = row['RAM']
            request_dict['floatingip'] = row['Floating IPs']
            request_dict['network'] = row['Networks']
            request_dict['port'] = row['Ports']
            request_dict['volumes'] = row['Volumes']
            request_dict['snapshots'] = row['Snapshots']
            request_dict['gigabytes'] = row['Volume & Snapshot Storage']
    return request_dict
 

def isolate_requests(dict_with_blanks):  # singles out the requests
    configured_dict = {k: v for k, v in dict_with_blanks.items() if v}
    if 'ram' in configured_dict.keys():
        configured_dict['ram'] = str(int(configured_dict['ram']) * 1024)
    return configured_dict


def compare_request_with_real(requested_quotas, all_quotas):
    for key in requested_quotas:
        if int(requested_quotas[key]) == all_quotas[key]:
            continue
        else:
            return False
    return True


parser = argparse.ArgumentParser()
parser.add_argument('filename')
parser.add_argument('config', nargs='?')
args = parser.parse_args()

if args.config:
    CONFIG_FILE = args.config
    config = ConfigParser.ConfigParser()
    config.read(CONFIG_FILE)
    admin_user = config.get('auth', 'admin_user')
    admin_pwd = config.get('auth', 'admin_pwd')
    admin_project = config.get('auth', 'admin_project')
    auth_url = config.get('auth', 'auth_url')
else:
    admin_user = os.environ.get('OS_USERNAME')
    admin_pwd = os.environ.get('OS_PASSWORD')
    admin_project = os.environ.get('OS_TENANT_NAME')
    auth_url = os.environ.get('OS_AUTH_URL')


auth = v2.Password(auth_url=auth_url,
                   username=admin_user,
                   password=admin_pwd,
                   tenant_name=admin_project)

sess = session.Session(auth=auth)
keystone = client.Client(session=sess)
ks_projects = keystone.projects.list()
neutron = nclient.Client(session=sess)
nova = novaclient.Client(2, session=sess)
cinder = cinderclient.Client(session=sess)

with open(args.filename, "rb") as source:
    READER = list(csv.DictReader(source))

MOC_STANDARDS = {'subnet': 10, 'router': 10, 'port': 10, 'network': 5,
                 'floatingip': 2, 'security_group': -1,
                 'security_group_rule': -1, 'ram': 51200, 'gigabytes': 1000,
                 'snapshots': 10, 'volumes': 10,
                 'injected_file_content_bytes': 10240, 'injected_files': 5,
                 'metadata_items': 128, 'instances': 10, 'cores': 20}

all_neutron_quotas = neutron.list_quotas()['quotas']
no_rec_of_request = []

for qset in all_neutron_quotas:
    proj_id = qset['tenant_id']

    try:
        project = keystone.projects.get(proj_id)
        nova_quotas = nova.quotas.get(proj_id).to_dict()
        cinder_quotas = cinder.quotas.get(proj_id).to_dict()
        actual_quotas = to_single_dict(nova_quotas, cinder_quotas, qset)

        if diff_moc_quotas(actual_quotas):

            quota_updates = proj_to_request_dict(project.name)
            isolated_requests = isolate_requests(quota_updates)

            unique_quotas = diff_moc_quotas(actual_quotas)

            if len(unique_quotas) > len(isolated_requests):  # partial request
                print "%s's request doesn't match quotas." % project.name
                no_rec_of_request.append(project.name)
                continue

            if compare_request_with_real(isolated_requests, actual_quotas):
                print "%s's request matches its quotas." % project.name
            else:
                print "%s's request doesn't match quotas." % project.name
                no_rec_of_request.append(project.name)

        else:
            print "%s has the default quotas." % project.name

    except NotFound:
        # it seems when projects are deleted their quota sets are not ?
        print "%s not found" % proj_id
print "No record of request for increase: %s" % no_rec_of_request
