import os
import mock

# This is a hack for now until directory structure is sorted
# When this is removed remember to un-ignore E402 in flake8
import sys
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.abspath(os.path.join(TEST_DIR, os.pardir))
sys.path.insert(0, PROJECT_DIR)

from quotas import QuotaManager, _group_quotas


def _fill_dict(key_list):
    """Fill a dictionary with sequential integers """
    full_dict = dict()
    for idx, key in enumerate(key_list):
        full_dict[key] = idx

    return full_dict


def test_group_quotas():
    """Test whether quotas are sorted correctly"""
        
    neutron = ['subnet', 'network', 'floatingip', 'subnetpool',
               'security_group_rule', 'security_group', 'router',
               'rbac_policy', 'port']
    
    nova = ['cores', 'injected_file_content_bytes',
            'inject_file_path_bytes', 'injected_files', 'instances',
            'key_pairs', 'metadata_items', 'ram']

    cinder = ['gigabytes', 'snapshots', 'volumes', 'backup_gigabytes',
              'backups', 'per_volume_gigabytes']

    neutron_dict = _fill_dict(neutron)
    nova_dict = _fill_dict(nova)
    cinder_dict = _fill_dict(cinder)
    
    all_dict = dict()
    all_dict.update(neutron_dict)
    all_dict.update(nova_dict)
    all_dict.update(cinder_dict)
    
    grouped = _group_quotas(**all_dict)
    
    matches = set(grouped['nova'].items()) & set(nova_dict.items())
    assert len(matches) == len(nova)
    
    matches = set(grouped['neutron'].items()) & set(neutron_dict.items())
    assert len(matches) == len(neutron)
    
    matches = set(grouped['cinder'].items()) & set(cinder_dict.items())
    assert len(matches) == len(cinder)


@mock.patch('quotas.cinderclient.Client')
@mock.patch('quotas.novaclient.Client')
@mock.patch('quotas.neutronclient.Client')
def test_modify(mock_neutron, mock_nova, mock_cinder):
    """Test the function that modifies quotas"""

    tenant_id = '1234ABCD5678EFGH'

    qm = QuotaManager(session=None, nova_version=2)

    qm.modify_quotas(tenant_id, floatingip=3, cores=4, snapshots=5)
    
    body = {'quota': {'floatingip': 3}}
    mock_neutron.return_value.update_quota.assert_called_with(tenant_id,
                                                              body=body)
                                          
    mock_nova.return_value.quotas.update.assert_called_with(tenant_id,
                                                            cores=4)
    mock_cinder.return_value.quotas.update.assert_called_with(tenant_id,
                                                              snapshots=5)
