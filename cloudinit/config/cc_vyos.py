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
import subprocess

from ipaddress import IPv4Network
from cloudinit import stages
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
        log.debug("No keys found.")
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


def set_config_interfaces(config, interface):
    for item in interface['subnets']:
        if item['type'] == 'static':
            if 'address' in item and runcommand("/usr/bin/ipaddrcheck --is-ipv4 " +  item['address']) == 0:
                cidr = str(IPv4Network('0.0.0.0/' + item['netmask']).prefixlen)
                ipcidr = item['address'] + '/' + cidr
                config.set(['interfaces', 'ethernet', interface['name'], 'address'], value=ipcidr, replace=True)
                config.set_tag(['interfaces', 'ethernet'])
                if item['gateway']:
                    config.set(['protocols', 'static', 'route', '0.0.0.0/0', 'next-hop'], value=item['gateway'], replace=True)
                    config.set_tag(['protocols', 'static', 'route'])
                    config.set_tag(['protocols', 'static', 'route', '0.0.0.0/0', 'next-hop'])

            if 'address' in item and runcommand("/usr/bin/ipaddrcheck --is-ipv6 " +  item['address']) == 0:
                config.set(['interfaces', 'ethernet', interface['name'], 'address'], value=item['address'], replace=False)
                config.set_tag(['interfaces', 'ethernet'])
                if item['gateway']:
                    config.set(['protocols', 'static', 'route6', '::/0', 'next-hop'], value=item['gateway'], replace=True)
                    config.set_tag(['protocols', 'static', 'route6'])
                    config.set_tag(['protocols', 'static', 'route6', '::/0', 'next-hop'])
        else:
            config.set(['interfaces', 'ethernet', interface['name'], 'address'], value='dhcp', replace=True)
            config.set_tag(['interfaces', 'ethernet'])


def set_config_nameserver(config, log, interface):
    if 'address' in interface:
        for server in interface['address']:
            config.set(['system', 'name-server'], value=server, replace=False)
    else:
        log.debug("No name-servers found.")
    if 'search' in interface: 
        for server in interface['search']:
            config.set(['system', 'domain-search'], value=server, replace=False)
    else:
        log.debug("No search-domains found.")


def set_config_dhcp(config):
    config.set(['interfaces', 'ethernet', 'eth0', 'address'], value='dhcp', replace=True)
    config.set_tag(['interfaces', 'ethernet'])


def set_config_ssh(config):
    config.set(['service', 'ssh'], replace=True)
    config.set(['service', 'ssh', 'port'], value='22', replace=True)
    config.set(['service', 'ssh', 'client-keepalive-interval'], value='180', replace=True)


def set_config_hostname(config, hostname):
    config.set(['system', 'host-name'], value=hostname, replace=True)


def set_config_cloud(config, hostname):
    config.set(['service', 'ssh'], replace=True)
    config.set(['service', 'ssh', 'port'], value='22', replace=True)
    config.set(['service', 'ssh', 'client-keepalive-interval'], value='180', replace=True)
    config.set(['interfaces', 'ethernet', 'eth0', 'address'], value='dhcp', replace=True)
    config.set_tag(['interfaces', 'ethernet'])
    config.set(['system', 'host-name'], value=hostname, replace=True)


def runcommand(cmd):
    proc = subprocess.Popen(cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            shell=True,
                            universal_newlines=True)
    std_out, std_err = proc.communicate()
    return proc.returncode


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
                set_ssh_login(config, log, user, ssh_key, key_x)
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
                set_ssh_login(config, log, user, ssh_key, key_x)
                key_x = key_x + 1

    if 'OVF' in dc.dsname:
        set_config_ovf(config, hostname, metadata)
    elif netcfg:
        for interface in netcfg['config']: 
            if interface['type'] == 'physical':
                key_y = 1
                set_config_interfaces(config, interface)
            
            if interface['type'] == 'nameserver':
                set_config_nameserver(config, log, interface)

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
        util.logexc(log, "Failed to write configs into file %s error %s", file_name, e)
