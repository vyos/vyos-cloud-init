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
import re
import sys
import ast

import ipaddress
from cloudinit import stages
from cloudinit import util

from cloudinit.distros import ug_util
from cloudinit.settings import PER_INSTANCE
from cloudinit import handlers
from cloudinit import log as logging

from vyos.configtree import ConfigTree

# configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

frequency = PER_INSTANCE

class VyosError(Exception):
    """Raised when the distro runs into an exception when setting vyos config.
    This may happen when the ssh pub key format is wrong.
    """
    pass

# configure user account with password
def set_pass_login(config, user, password, encrypted_pass):
    if encrypted_pass:
        config.set(['system', 'login', 'user', user, 'authentication', 'encrypted-password'], value=password, replace=True)
    else:
        config.set(['system', 'login', 'user', user, 'authentication', 'plaintext-password'], value=password, replace=True)

    config.set_tag(['system', 'login', 'user'])

# configure user account with ssh key
def set_ssh_login(config, user, key_string, key_x):
    key_type = None
    key_data = None
    key_name = None

    if key_string  == '':
        logger.error("No keys found.")
        return

    key_parts = key_string.split(None)

    for key in key_parts:
        if 'ssh-dss' in key or 'ssh-rsa' in key:
            key_type = key

        if key.startswith('AAAAB3NzaC1yc2E') or key.startswith('AAAAB3NzaC1kc3M'):
           key_data = key

    if not key_type:
        logger.error("Key type not defined, wrong ssh key format.")
        return

    if not key_data:
        logger.error("Key base64 not defined, wrong ssh key format.")
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


# configure system parameters from OVF template
def set_config_ovf(config, hostname, metadata):
    ip_0 = metadata['ip0'] 
    mask_0 = metadata['netmask0']
    gateway = metadata['gateway']
    DNS = list(metadata['DNS'].replace(' ', '').split(','))
    NTP = list(metadata['NTP'].replace(' ', '').split(','))
    APIKEY = metadata['APIKEY']
    APIPORT = metadata['APIPORT']
    APIDEBUG = metadata['APIDEBUG']

    if ip_0 and ip_0 != 'null' and mask_0 and mask_0 != 'null' and gateway and gateway != 'null': 
        cidr = str(ipaddress.IPv4Network('0.0.0.0/' + mask_0).prefixlen) 
        ipcidr = ip_0 + '/' + cidr

        config.set(['interfaces', 'ethernet', 'eth0', 'address'], value=ipcidr, replace=True)
        config.set_tag(['interfaces', 'ethernet'])
        config.set(['protocols', 'static', 'route', '0.0.0.0/0', 'next-hop'], value=gateway, replace=True)
        config.set_tag(['protocols', 'static', 'route'])
        config.set_tag(['protocols', 'static', 'route', '0.0.0.0/0', 'next-hop'])
    else:
        config.set(['interfaces', 'ethernet', 'eth0', 'address'], value='dhcp', replace=True)
        config.set_tag(['interfaces', 'ethernet'])

    DNS = [server for server in DNS if server and server != 'null']
    if DNS:
        for server in DNS:
            config.set(['system', 'name-server'], value=server, replace=False)

    NTP = [server for server in NTP if server and server != 'null']
    if NTP:
        for server in NTP:
            config.set(['system', 'ntp', 'server'], value=server, replace=False)
        config.set_tag(['system', 'ntp', 'server'])

    if APIKEY and APIKEY != 'null':
        config.set(['service', 'https', 'api', 'keys', 'id', 'cloud-init', 'key'], value=APIKEY, replace=True)
        config.set_tag(['service', 'https', 'api', 'keys', 'id'])

    if APIDEBUG != 'False' and APIKEY and APIKEY != 'null':
        config.set(['service', 'https', 'api', 'debug'], replace=True)

    if APIPORT and APIPORT != 'null' and APIKEY and APIKEY != 'null':
        config.set(['service', 'https', 'listen-address', '0.0.0.0', 'listen-port'], value=APIPORT, replace=True)
        config.set_tag(['service', 'https', 'listen-address'])

    config.set(['service', 'ssh'], replace=True)
    config.set(['service', 'ssh', 'port'], value='22', replace=True)
    
    if hostname and hostname != 'null':
        config.set(['system', 'host-name'], value=hostname, replace=True)
    else:
        config.set(['system', 'host-name'], value='vyos', replace=True)


# configure interface
def set_config_interfaces(config, iface_name, iface_config):
    # configure DHCP client
    if 'dhcp4' in iface_config:
        if iface_config['dhcp4'] == True:
            config.set(['interfaces', 'ethernet', iface_name, 'address'], value='dhcp', replace=True)
            config.set_tag(['interfaces', 'ethernet'])
    if 'dhcp6' in iface_config:
        if iface_config['dhcp6'] == True:
            config.set(['interfaces', 'ethernet', iface_name, 'address'], value='dhcp6', replace=True)
            config.set_tag(['interfaces', 'ethernet'])

    # configure static addresses
    if 'addresses' in iface_config:
        for item in iface_config['addresses']:
            config.set(['interfaces', 'ethernet', iface_name, 'address'], value=item, replace=True)
            config.set_tag(['interfaces', 'ethernet'])

    # configure gateways
    if 'gateway4' in iface_config:
        config.set(['protocols', 'static', 'route', '0.0.0.0/0', 'next-hop'], value=item, replace=True)
        config.set_tag(['protocols', 'static', 'route'])
        config.set_tag(['protocols', 'static', 'route', '0.0.0.0/0', 'next-hop'])
    if 'gateway6' in iface_config:
        config.set(['protocols', 'static', 'route6', '::/0', 'next-hop'], value=item, replace=True)
        config.set_tag(['protocols', 'static', 'route6'])
        config.set_tag(['protocols', 'static', 'route6', '::/0', 'next-hop'])

    # configre MTU
    if 'mtu' in iface_config:
        config.set(['interfaces', 'ethernet', iface_name, 'mtu'], value=iface_config['mtu'], replace=True)
        config.set_tag(['interfaces', 'ethernet'])

    # configure routes
    if 'routes' in iface_config:
        for item in iface_config['routes']:
            try:
                if ipaddress.ip_network(item['to']).version == 4:
                    config.set(['protocols', 'static', 'route', item['to'], 'next-hop'], value=item['via'], replace=True)
                    config.set_tag(['protocols', 'static', 'route'])
                    config.set_tag(['protocols', 'static', 'route', item['to'], 'next-hop'])
                if ipaddress.ip_network(item['to']).version == 6:
                    config.set(['protocols', 'static', 'route6', item['to'], 'next-hop'], value=item['via'], replace=True)
                    config.set_tag(['protocols', 'static', 'route6'])
                    config.set_tag(['protocols', 'static', 'route6', item['to'], 'next-hop'])
            except Exception as err:
                logger.error("Impossible to detect IP protocol version: {}".format(err))

    # configure nameservers
    if 'nameservers' in iface_config:
        if 'search' in iface_config['nameservers']:
            for item in iface_config['nameservers']['search']:
                config.set(['system', 'domain-search'], value=item, replace=False)
        if 'addresses' in iface_config['nameservers']:
            for item in iface_config['nameservers']['addresses']:
                config.set(['system', 'name-server'], value=item, replace=False)


# configure DHCP client for interface
def set_config_dhcp(config):
    config.set(['interfaces', 'ethernet', 'eth0', 'address'], value='dhcp', replace=True)
    config.set_tag(['interfaces', 'ethernet'])


# configure SSH server service
def set_config_ssh(config):
    config.set(['service', 'ssh'], replace=True)
    config.set(['service', 'ssh', 'port'], value='22', replace=True)
    config.set(['service', 'ssh', 'client-keepalive-interval'], value='180', replace=True)


# configure hostname
def set_config_hostname(config, hostname):
    config.set(['system', 'host-name'], value=hostname, replace=True)


# configure SSH, eth0 interface and hostname
def set_config_cloud(config, hostname):
    config.set(['service', 'ssh'], replace=True)
    config.set(['service', 'ssh', 'port'], value='22', replace=True)
    config.set(['service', 'ssh', 'client-keepalive-interval'], value='180', replace=True)
    config.set(['interfaces', 'ethernet', 'eth0', 'address'], value='dhcp', replace=True)
    config.set_tag(['interfaces', 'ethernet'])
    config.set(['system', 'host-name'], value=hostname, replace=True)


# main config handler
def handle(name, cfg, cloud, log, _args):
    init = stages.Init()
    dc = init.fetch()
    cfg_file_name = '/opt/vyatta/etc/config/config.boot'
    bak_file_name = '/opt/vyatta/etc/config.boot.default'
    metadata = cloud.datasource.metadata
    (netcfg, _) = init._find_networking_config()
    (users, _) = ug_util.normalize_users_groups(cfg, cloud.distro)
    (hostname, _) = util.get_hostname_fqdn(cfg, cloud)
    key_x = 1
    key_y = 0

    # look at data that can be used for configuration
    #print(dir(dc))

    if not os.path.exists(cfg_file_name):
        file_name = bak_file_name
    else:
        file_name = cfg_file_name

    with open(file_name, 'r') as f:
        config_file = f.read()
    config = ConfigTree(config_file)

    if 'Azure' in dc.dsname: 
        encrypted_pass = True
        for key, val in users.items():
            user = key

            if 'passwd' in val:
                password = val.get('passwd')
                set_pass_login(config, user, password, encrypted_pass)

            vyos_keys = metadata['public-keys']

            for ssh_key in vyos_keys:
                set_ssh_login(config, user, ssh_key, key_x)
                key_x = key_x + 1
    else:
        encrypted_pass = False
        for user in users:
            password = util.get_cfg_option_str(cfg, 'passwd', None)

            if not password:
                password = util.get_cfg_option_str(cfg, 'password', None)

            if password and password != '':
                hash = re.match("(^\$.\$)", password)
                hash_count = password.count('$')
                if hash and hash_count >= 3:
                    base64 = password.split('$')[3]
                    base_64_len = len(base64)
                    if ((hash.group(1) == '$1$' and base_64_len == 22) or
                        (hash.group(1) == '$5$' and base_64_len == 43) or
                        (hash.group(1) == '$6$' and base_64_len == 86)):
                        encrypted_pass = True
                set_pass_login(config, user, password, encrypted_pass)

            vyos_keys = cloud.get_public_ssh_keys() or []
            if 'ssh_authorized_keys' in cfg:
                cfgkeys = cfg['ssh_authorized_keys']
                vyos_keys.extend(cfgkeys)

            for ssh_key in vyos_keys:
                set_ssh_login(config, user, ssh_key, key_x)
                key_x = key_x + 1

    if 'OVF' in dc.dsname:
        set_config_ovf(config, hostname, metadata)
        key_y = 1
    elif netcfg:
        if 'ethernets' in netcfg:
            key_y = 1
            for interface_name, interface_config in netcfg['ethernets'].items():
                set_config_interfaces(config, interface_name, interface_config)

        set_config_ssh(config)
        set_config_hostname(config, hostname)
    else:
        set_config_dhcp(config) 
        set_config_ssh(config)
        set_config_hostname(config, hostname)

    if key_y == 0:
        set_config_dhcp(config)

    try:
        with open(cfg_file_name, 'w') as f:
            f.write(config.to_string())
    except Exception as e:
        logger.error("Failed to write configs into file %s error %s", file_name, e)
