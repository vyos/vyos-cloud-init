# vi: ts=4 expandtab
#
#    Copyright (C) 2009-2010 Canonical Ltd.
#    Copyright (C) 2012 Hewlett-Packard Development Company, L.P.
#    Copyright (C) 2019 Sentrium S.L.
#
#    Author: Scott Moser <scott.moser@canonical.com>
#    Author: Juerg Haefliger <juerg.haefliger@hp.com>
#    Author: Kim Hagen <kim@sentrium.io>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 3, as
#    published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys
import ast

from ipaddress import IPv4Network
from cloudinit import util

from cloudinit.distros import ug_util
from cloudinit.settings import PER_INSTANCE

from vyos.configtree import ConfigTree

frequency = PER_INSTANCE

class VyosError(Exception):
    """Raised when the distro runs into an exception when setting vyos config.
    This may happen when the ssh pub key format is wrong.
    """
    pass

def set_pass_login(config, user, password, encrypted_pass):
    if encrypted_pass:
        config.set(['system', 'login', 'user', user, 'authentication', 'encrypted-password'], value=password, replace=True)
    else:
        config.set(['system', 'login', 'user', user, 'authentication', 'plaintext-password'], value=password, replace=True)

    config.set_tag(['system', 'login', 'user'])
    config.set(['system', 'login', 'user', user, 'level'], value='admin', replace=True)


def set_ssh_login(config, log, user, key_string, key_x):
    key_type = None
    key_data = None
    key_name = None

    if key_string  == '':
        return

    key_parts = key_string.split(None)

    for key in key_parts:
        if 'ssh-dss' in key or 'ssh-rsa' in key:
            key_type = key

        if key.startswith('AAAAB3NzaC1yc2E') or key.startswith('AAAAB3NzaC1kc3M'):
           key_data = key

    if not key_type:
        util.logexc(log, 'Key type not defined, wrong ssh key format.')
        return

    if not key_data:
        util.logexc(log, 'Key base64 not defined, wrong ssh key format.')
        return

    if len(key_parts) > 2:
        if key_parts[2] != key_type or key_parts[2] != key_data:
            key_name = key_parts[2]
        else:
            key_name = "cloud-init-%s" % key_x
    else:
        key_name = "cloud-init-%s" % key_x

    config.set(['system', 'login', 'user', user, 'authentication', 'public-keys', key_name , 'key'], value=key_data, replace=True)
    config.set(['system', 'login', 'user', user, 'authentication', 'public-keys', key_name , 'type'], value=key_type, replace=True)
    config.set_tag(['system', 'login', 'user'])
    config.set_tag(['system', 'login', 'user', user, 'authentication', 'public-keys'])
    config.set(['system', 'login', 'user', user, 'level'], value='admin', replace=True)  


def set_config_cloud(config, hostname):
    config.set(['service', 'ssh'], replace=True)
    config.set(['service', 'ssh', 'port'], value='22', replace=True)
    config.set(['service', 'ssh', 'client-keepalive-interval'], value='180', replace=True)
    config.set(['interfaces', 'ethernet', 'eth0', 'address'], value='dhcp', replace=True)
    config.set_tag(['interfaces', 'ethernet'])
    config.set(['system', 'host-name'], value=hostname, replace=True)


def set_config_ovf(config, hostname, metadata):
    ip_0 = metadata['ip0'] 
    mask_0 = metadata['netmask0']
    gateway = metadata['gateway']
    DNS = list(metadata['DNS'].replace(' ', '').split(','))
    NTP = list(metadata['NTP'].replace(' ', '').split(','))

    if ip_0 != '' and mask_0 != '' and gateway != '': 
        cidr = str(IPv4Network('0.0.0.0/' + mask_0).prefixlen) 
        ipcidr = ip_0 + '/' + cidr

        config.set(['interfaces', 'ethernet', 'eth0', 'address'], value=ipcidr, replace=True)
        config.set_tag(['interfaces', 'ethernet'])
        config.set(['protocols', 'static', 'route', '0.0.0.0/0', 'next-hop'], value=gateway, replace=True)
        config.set_tag(['protocols', 'static', 'route'])
        config.set_tag(['protocols', 'static', 'route', '0.0.0.0/0', 'next-hop'])
    else:
        config.set(['interfaces', 'ethernet', 'eth0', 'address'], value='dhcp', replace=True)
        config.set_tag(['interfaces', 'ethernet'])

    DNS = [ server for server in DNS if server != '' ]
    if DNS:
        for server in DNS:
            config.set(['system', 'name-server'], value=server, replace=False)

    NTP = [ server for server in NTP if server != '' ]
    if NTP:
        for server in NTP:
            config.set(['system', 'ntp', 'server'], value=server, replace=False)
        config.set_tag(['system', 'ntp', 'server'])

    config.set(['service', 'ssh'], replace=True)
    config.set(['service', 'ssh', 'port'], value='22', replace=True)
    
    if hostname != '':
        config.set(['system', 'host-name'], value=hostname, replace=True)


def handle(name, cfg, cloud, log, _args):
    cfg_file_name = '/opt/vyatta/etc/config/config.boot'
    bak_file_name = '/opt/vyatta/etc/config.boot.default'
    metadata = cloud.datasource.metadata
    (users, groups) = ug_util.normalize_users_groups(cfg, cloud.distro)
    (hostname, fqdn) = util.get_hostname_fqdn(cfg, cloud)
    encrypted_pass = False
    key_x = 1

    if not os.path.exists(cfg_file_name):
        file_name = bak_file_name
    else:
        file_name = cfg_file_name

    with open(file_name, 'r') as f:
        config_file = f.read()
    config = ConfigTree(config_file)

    if 'Azure' in str(cloud.datasource):
        encrypted_pass = True
        for key, val in users.items():
            user = key
            if 'passwd' in val:
                password = val.get('passwd')
                set_pass_login(config, user, password, encrypted_pass)

            vyos_keys = metadata['public-keys']
            for ssh_key in vyos_keys:
                set_ssh_login(config, log, user, ssh_key, key_x)
                key_x = key_x + 1
        set_config_cloud(config, hostname) 
    elif 'OVF' in str(cloud.datasource):
        for user in users:
            password = util.get_cfg_option_str(cfg, 'password', None)
            if password and password != '':
                set_pass_login(config, user, password, encrypted_pass)

            vyos_keys = cloud.get_public_ssh_keys() or []
            if 'ssh_authorized_keys' in cfg:
                cfgkeys = cfg['ssh_authorized_keys']
                vyos_keys.extend(cfgkeys)

            for ssh_key in vyos_keys:
                set_ssh_login(config, log, user, ssh_key, key_x)
                key_x = key_x + 1
        set_config_ovf(config, hostname, metadata)
    else:        
        for user in users:
            password = util.get_cfg_option_str(cfg, 'passwd', None)
            if password:
                set_pass_login(config, user, password, encrypted_pass)

            vyos_keys = cloud.get_public_ssh_keys() or []
            if 'ssh_authorized_keys' in cfg:
                cfgkeys = cfg['ssh_authorized_keys']
                vyos_keys.extend(cfgkeys)

            for ssh_key in vyos_keys:
                set_ssh_login(config, log, user, ssh_key, key_x)
                key_x = key_x + 1
        set_config_cloud(config, hostname) 

    try:
        with open(cfg_file_name, 'w') as f:
            f.write(config.to_string())
    except:
        util.logexc(log, "Failed to write configs into file %s", file_name)
