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
"""Manage OpenStack project quotas controlled by multiple reasources.

The QuotaManager class abstracts quota management so that the calling script
is not required to understand which quotas are controlled by which services.
"""
from novaclient import client as novaclient
from neutronclient.v2_0 import client as neutronclient
from cinderclient.v2 import client as cinderclient


class QuotaManager:
    """Manages resource quotas for multiple OpenStack resources"""
    def __init__(self, session, nova_version):
        self.nova = novaclient.Client(nova_version, session=session)
        self.neutron = neutronclient.Client(session=session)
        self.cinder = cinderclient.Client(session=session)
  
    def get_current(self, proj_id):
        """ Get the current quotas for multiple services"""
        nova = self.nova.quotas.get(proj_id).to_dict()
        neutron = self.neutron.show_quota(proj_id)['quota']
        cinder = self.cinder.quotas.get(proj_id)._info
        current_quotas = _get_single_dict(nova, neutron, cinder)
        return current_quotas

    def modify_quotas(self, project_id, **kwargs):
        """Set quota values for the given project."""
        new_quotas = _group_quotas(**kwargs)

        # If no update is given for ports but related quotas are updated, check
        # whether ports should also be updated. Users don't necessarily know to
        # to ask for this
        if 'port' not in kwargs and ('instances' in kwargs or
                                     'network' in kwargs):
            new_port_quota = self._check_port_quota(project_id, **kwargs)
            if new_port_quota:
                new_quotas['neutron']['port'] = new_port_quota
                # `TODO: Get the project object passed into this function,
                # so we can use the name instead of the ID here
                print ("NOTICE: Auto-adjusted port quota to {} "
                       "for project {}").format(new_port_quota, project_id)
        
        neutron_quotas = {"quota": new_quotas['neutron']}
        new_neutron = self.neutron.update_quota(project_id,
                                                body=neutron_quotas)
        new_nova = self.nova.quotas.update(project_id, **new_quotas['nova'])
        new_cinder = self.cinder.quotas.update(project_id,
                                               **new_quotas['cinder'])
 
        all_quotas = _get_single_dict(new_nova, new_neutron, new_cinder)
        return all_quotas

    def _check_port_quota(self, project_id, **kwargs):
        """Check whether quota updates should trigger a port quota update.

        Users may ask to increase to their instance or network quota without
        knowing that their ports quota should also be increased.  Ensure they
        will have enough ports to use the other increases.
        """
        current_quotas = self.get_current(project_id)
        add_port_count = 0

        if ('network') in kwargs:
            # Increase port quota by 2 for each new network to allow for
            # one DHCP port and one router interface
            added_networks = kwargs['network'] - current_quotas['network']
            add_port_count = added_networks * 2
        
        if ('instances' in kwargs):
            # Get a count of existing ports not used by instances
            port_list = self.neutron.list_ports(project=project_id)['ports']
            non_compute_ports_used = len([p for p in port_list if
                                          p['device_owner'] != 'compute:nova'])
            
            # Check whether we will have at least 1 port per instance
            # TODO: do we want to add some 'padding' ports here?
            min_ports_needed = kwargs['instances'] + non_compute_ports_used
            if (current_quotas['port']) < min_ports_needed:
                quota_gap = min_ports_needed - current_quotas['port']
                add_port_count += quota_gap

        if add_port_count:
            return (current_quotas['port'] + add_port_count)
        else:
            return False

 
def _get_single_dict(nova, neutron, cinder):
    """Create a single dictionary of quota values"""
    if type(nova) is not dict:
        nova = nova.to_dict()
    
    if type(cinder) is not dict:
        cinder = cinder.to_dict()

    single_dict = nova
    single_dict.update(neutron)
    single_dict.update(cinder)

    return single_dict


def _group_quotas(**kwargs):
    """Group the quota keywords by service
    
    NOTE: novaclient.quotas.get() reports dummy values for the following
    even when neutron is managing networks:
        floating_ips, security_group_rules, security_groups
    
    If networks are managed by neutron, the values reported by nova are
    not accurate, and updates made via novaclient have no effect
    """

    # Quotas managed by neutronclient
    neutron = ['subnet', 'network', 'floatingip', 'subnetpool',
               'security_group_rule', 'security_group', 'router',
               'rbac_policy', 'port']

    # Quotas managed by novaclient
    # TODO: Test whether novaclient manages these quotas:
    #    fixed_ips, server_group_members, server_groups
    nova = ['cores', 'injected_file_content_bytes',
            'inject_file_path_bytes', 'injected_files', 'instances',
            'key_pairs', 'metadata_items', 'ram']

    # Quotas managed by cinderclient
    cinder = ['gigabytes', 'snapshots', 'volumes', 'backup_gigabytes',
              'backups', 'per_volume_gigabytes']

    quotas = {'neutron': dict(), 'nova': dict(), 'cinder': dict()}

    for key in kwargs:
        if key in nova:
            quotas['nova'][key] = kwargs[key]
        elif key in neutron:
            quotas['neutron'][key] = kwargs[key]
        elif key in cinder:
            quotas['cinder'][key] = kwargs[key]
        else:
            warning = ("\tWARNING: Unrecognized quota"
                       "'{0}={1}'").format(key, kwargs[key])
            print warning

    return quotas
