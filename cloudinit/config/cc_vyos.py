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
import ipaddress
from cloudinit import stages
from cloudinit import util
from cloudinit.distros import ug_util
from cloudinit.settings import PER_INSTANCE
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
        logger.debug("Configuring encrypted password for: {}".format(user))
        config.set(['system', 'login', 'user', user, 'authentication', 'encrypted-password'], value=password, replace=True)
    else:
        logger.debug("Configuring clear-text password for: {}".format(user))
        config.set(['system', 'login', 'user', user, 'authentication', 'plaintext-password'], value=password, replace=True)

    config.set_tag(['system', 'login', 'user'])


# configure user account with ssh key
def set_ssh_login(config, user, key_string, ssh_key_number):
    key_type = None
    key_data = None
    key_name = None

    if key_string == '':
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
            key_name = "cloud-init-%s" % ssh_key_number
    else:
        key_name = "cloud-init-%s" % ssh_key_number

    logger.debug("Configuring SSH {} public key for: {}".format(key_type, user))
    config.set(['system', 'login', 'user', user, 'authentication', 'public-keys', key_name, 'key'], value=key_data, replace=True)
    config.set(['system', 'login', 'user', user, 'authentication', 'public-keys', key_name, 'type'], value=key_type, replace=True)
    config.set_tag(['system', 'login', 'user'])
    config.set_tag(['system', 'login', 'user', user, 'authentication', 'public-keys'])


# filter hostname to be sure that it can be applied
# NOTE: here we cannot attempt to deny anything prohibited, as it is too late.
# Therefore, we need only pass what is allowed, cutting everything else
def hostname_filter(hostname):
    # define regex for alloweed characters and resulted hostname
    regex_characters = re.compile(r'[a-z0-9.-]', re.IGNORECASE)
    regex_hostname = re.compile(r'[a-z0-9](([a-z0-9-]\.|[a-z0-9-])*[a-z0-9])?', re.IGNORECASE)
    # filter characters
    filtered_characters = ''.join(regex_characters.findall(hostname))
    # check that hostname start and end by allowed characters and cut unsupported ones, limit to 64 characters total
    filtered_hostname = regex_hostname.search(filtered_characters).group()[:64]

    if hostname != filtered_hostname:
        logger.warning("Hostname was filtered: {} -> {}".format(hostname, filtered_hostname))
    # return safe to apply host-name value
    return filtered_hostname


# configure system parameters from OVF template
def set_config_ovf(config, metadata):
    logger.debug("Applying configuration from an OVF template")

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


# configure interface from networking config version 1
def set_config_interfaces_v1(config, iface_config):
    # configure physical interfaces
    if iface_config['type'] == 'physical':
        iface_name = iface_config['name']
        # configre MTU
        if 'mtu' in iface_config:
            logger.debug("Setting MTU for {}: {}".format(iface_name, iface_config['mtu']))
            config.set(['interfaces', 'ethernet', iface_name, 'mtu'], value=iface_config['mtu'], replace=True)
            config.set_tag(['interfaces', 'ethernet'])

        # configure subnets
        if 'subnets' in iface_config:
            # if DHCP is already configured, we should ignore all other addresses, as in VyOS it is impossible to use both on the same interface
            dhcp4_configured = False
            dhcp6_configured = False
            for subnet in iface_config['subnets']:
                # configure DHCP client
                if subnet['type'] in ['dhcp', 'dhcp4', 'dhcp6']:
                    if subnet['type'] == 'dhcp6':
                        logger.debug("Configuring DHCPv6 for {}".format(iface_name))
                        config.set(['interfaces', 'ethernet', iface_name, 'address'], value='dhcp6', replace=True)
                        dhcp6_configured = True
                    else:
                        logger.debug("Configuring DHCPv4 for {}".format(iface_name))
                        config.set(['interfaces', 'ethernet', iface_name, 'address'], value='dhcp', replace=True)
                        dhcp4_configured = True

                    config.set_tag(['interfaces', 'ethernet'])
                    continue

                # configure static options
                if subnet['type'] in ['static', 'static6']:
                    # configure IP address
                    try:
                        ip_interface = ipaddress.ip_interface(subnet['address'])
                        ip_version = ip_interface.version
                        ip_address = ip_interface.ip.compressed
                        ip_static_addr = ''
                        # format IPv4
                        if ip_version == 4 and ip_address != '0.0.0.0' and dhcp4_configured is not True:
                            if '/' in subnet['address']:
                                ip_static_addr = ip_interface.compressed
                            else:
                                ip_static_addr = ipaddress.IPv4Interface('{}/{}'.format(ip_address, subnet['netmask'])).compressed
                        # format IPv6
                        if ip_version == 6 and dhcp6_configured is not True:
                            ip_static_addr = ip_interface.compressed
                        # apply to the configuration
                        if ip_static_addr:
                            logger.debug("Configuring static IP address for {}: {}".format(iface_name, ip_static_addr))
                            config.set(['interfaces', 'ethernet', iface_name, 'address'], value=ip_static_addr, replace=True)
                            config.set_tag(['interfaces', 'ethernet'])
                    except Exception as err:
                        logger.error("Impossible to configure static IP address: {}".format(err))

                    # configure gateway
                    if 'gateway' in subnet and subnet['gateway'] != '0.0.0.0':
                        logger.debug("Configuring gateway for {}: {}".format(iface_name, subnet['gateway']))
                        config.set(['protocols', 'static', 'route', '0.0.0.0/0', 'next-hop'], value=subnet['gateway'], replace=True)
                        config.set_tag(['protocols', 'static', 'route'])
                        config.set_tag(['protocols', 'static', 'route', '0.0.0.0/0', 'next-hop'])

                    # configure routes
                    if 'routes' in subnet:
                        for item in subnet['routes']:
                            try:
                                ip_network = ipaddress.ip_network('{}/{}'.format(item['network'], item['netmask']))
                                if ip_network.version == 4:
                                    logger.debug("Configuring IPv4 route on {}: {} via {}".format(iface_name, ip_network.compressed, item['gateway']))
                                    config.set(['protocols', 'static', 'route', ip_network.compressed, 'next-hop'], value=item['gateway'], replace=True)
                                    config.set_tag(['protocols', 'static', 'route'])
                                    config.set_tag(['protocols', 'static', 'route', item['to'], 'next-hop'])
                                if ip_network.version == 6:
                                    logger.debug("Configuring IPv6 route on {}: {} via {}".format(iface_name, ip_network.compressed, item['gateway']))
                                    config.set(['protocols', 'static', 'route6', ip_network.compressed, 'next-hop'], value=item['gateway'], replace=True)
                                    config.set_tag(['protocols', 'static', 'route6'])
                                    config.set_tag(['protocols', 'static', 'route6', item['to'], 'next-hop'])
                            except Exception as err:
                                logger.error("Impossible to detect IP protocol version: {}".format(err))

                    # configure nameservers
                    if 'dns_nameservers' in subnet:
                        for item in subnet['dns_nameservers']:
                            logger.debug("Configuring DNS nameserver for {}: {}".format(iface_name, item))
                            config.set(['system', 'name-server'], value=item, replace=False)

                    if 'dns_search' in subnet:
                        for item in subnet['dns_search']:
                            logger.debug("Configuring DNS search domain for {}: {}".format(iface_name, item))
                            config.set(['system', 'domain-search'], value=item, replace=False)


# configure interface from networking config version 2
def set_config_interfaces_v2(config, iface_name, iface_config):
    # configure DHCP client
    if 'dhcp4' in iface_config:
        if iface_config['dhcp4'] is True:
            logger.debug("Configuring DHCPv4 for {}".format(iface_name))
            config.set(['interfaces', 'ethernet', iface_name, 'address'], value='dhcp', replace=True)
            config.set_tag(['interfaces', 'ethernet'])
    if 'dhcp6' in iface_config:
        if iface_config['dhcp6'] is True:
            logger.debug("Configuring DHCPv6 for {}".format(iface_name))
            config.set(['interfaces', 'ethernet', iface_name, 'address'], value='dhcp6', replace=True)
            config.set_tag(['interfaces', 'ethernet'])

    # configure static addresses
    if 'addresses' in iface_config:
        for item in iface_config['addresses']:
            logger.debug("Configuring static IP address for {}: {}".format(iface_name, item))
            config.set(['interfaces', 'ethernet', iface_name, 'address'], value=item, replace=True)
            config.set_tag(['interfaces', 'ethernet'])

    # configure gateways
    if 'gateway4' in iface_config:
        logger.debug("Configuring IPv4 gateway for {}: {}".format(iface_name, iface_config['gateway4']))
        config.set(['protocols', 'static', 'route', '0.0.0.0/0', 'next-hop'], value=iface_config['gateway4'], replace=True)
        config.set_tag(['protocols', 'static', 'route'])
        config.set_tag(['protocols', 'static', 'route', '0.0.0.0/0', 'next-hop'])
    if 'gateway6' in iface_config:
        logger.debug("Configuring IPv6 gateway for {}: {}".format(iface_name, iface_config['gateway6']))
        config.set(['protocols', 'static', 'route6', '::/0', 'next-hop'], value=iface_config['gateway6'], replace=True)
        config.set_tag(['protocols', 'static', 'route6'])
        config.set_tag(['protocols', 'static', 'route6', '::/0', 'next-hop'])

    # configre MTU
    if 'mtu' in iface_config:
        logger.debug("Setting MTU for {}: {}".format(iface_name, iface_config['mtu']))
        config.set(['interfaces', 'ethernet', iface_name, 'mtu'], value=iface_config['mtu'], replace=True)
        config.set_tag(['interfaces', 'ethernet'])

    # configure routes
    if 'routes' in iface_config:
        for item in iface_config['routes']:
            try:
                if ipaddress.ip_network(item['to']).version == 4:
                    logger.debug("Configuring IPv4 route on {}: {} via {}".format(iface_name, item['to'], item['via']))
                    config.set(['protocols', 'static', 'route', item['to'], 'next-hop'], value=item['via'], replace=True)
                    config.set_tag(['protocols', 'static', 'route'])
                    config.set_tag(['protocols', 'static', 'route', item['to'], 'next-hop'])
                if ipaddress.ip_network(item['to']).version == 6:
                    logger.debug("Configuring IPv6 route on {}: {} via {}".format(iface_name, item['to'], item['via']))
                    config.set(['protocols', 'static', 'route6', item['to'], 'next-hop'], value=item['via'], replace=True)
                    config.set_tag(['protocols', 'static', 'route6'])
                    config.set_tag(['protocols', 'static', 'route6', item['to'], 'next-hop'])
            except Exception as err:
                logger.error("Impossible to detect IP protocol version: {}".format(err))

    # configure nameservers
    if 'nameservers' in iface_config:
        if 'search' in iface_config['nameservers']:
            for item in iface_config['nameservers']['search']:
                logger.debug("Configuring DNS search domain for {}: {}".format(iface_name, item))
                config.set(['system', 'domain-search'], value=item, replace=False)
        if 'addresses' in iface_config['nameservers']:
            for item in iface_config['nameservers']['addresses']:
                logger.debug("Configuring DNS nameserver for {}: {}".format(iface_name, item))
                config.set(['system', 'name-server'], value=item, replace=False)


# configure DHCP client for eth0 interface (fallback)
def set_config_dhcp(config):
    logger.debug("Configuring DHCPv4 on eth0 interface (fallback)")
    config.set(['interfaces', 'ethernet', 'eth0', 'address'], value='dhcp', replace=True)
    config.set_tag(['interfaces', 'ethernet'])


# configure SSH server service
def set_config_ssh(config):
    logger.debug("Configuring SSH service")
    config.set(['service', 'ssh'], replace=True)
    config.set(['service', 'ssh', 'port'], value='22', replace=True)
    config.set(['service', 'ssh', 'client-keepalive-interval'], value='180', replace=True)


# configure hostname
def set_config_hostname(config, hostname):
    logger.debug("Configuring hostname to: {}".format(hostname))
    config.set(['system', 'host-name'], value=hostname_filter(hostname), replace=True)


# main config handler
def handle(name, cfg, cloud, log, _args):
    init = stages.Init()
    dc = init.fetch()
    cfg_file_name = '/opt/vyatta/etc/config/config.boot'
    bak_file_name = '/opt/vyatta/etc/config.boot.default'
    metadata = cloud.datasource.metadata
    (netcfg, _) = init._find_networking_config()
    (users, _) = ug_util.normalize_users_groups(cfg, cloud.distro)
    (hostname, fqdn) = util.get_hostname_fqdn(cfg, cloud, metadata_only=True)
    ssh_key_number = 1
    network_configured = False

    # open configuration file
    if not os.path.exists(cfg_file_name):
        file_name = bak_file_name
    else:
        file_name = cfg_file_name

    logger.debug("Using configuration file: {}".format(file_name))
    with open(file_name, 'r') as f:
        config_file = f.read()
    config = ConfigTree(config_file)

    # configure system logins
    if 'Azure' in dc.dsname:
        logger.debug("Detected Azure environment")
        encrypted_pass = True
        for key, val in users.items():
            user = key

            if 'passwd' in val:
                password = val.get('passwd')
                set_pass_login(config, user, password, encrypted_pass)

            vyos_keys = metadata['public-keys']

            for ssh_key in vyos_keys:
                set_ssh_login(config, user, ssh_key, ssh_key_number)
                ssh_key_number = ssh_key_number + 1
    else:
        encrypted_pass = False
        for user in users:
            password = util.get_cfg_option_str(cfg, 'passwd', None)

            if not password:
                password = util.get_cfg_option_str(cfg, 'password', None)

            if password and password != '':
                hash = re.match(r"(^\$.\$)", password)
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
                set_ssh_login(config, user, ssh_key, ssh_key_number)
                ssh_key_number = ssh_key_number + 1

    # apply settings from OVF template
    if 'OVF' in dc.dsname:
        set_config_ovf(config, metadata)
        if hostname and hostname == 'null':
            hostname = 'vyos'
        network_configured = True

    # process networking configuration data
    if netcfg and network_configured is False:
        # check which one version of config we have
        # version 1
        if netcfg['version'] == 1:
            for interface_config in netcfg['config']:
                set_config_interfaces_v1(config, interface_config)
            network_configured = True

        # version 2
        if netcfg['version'] == 2:
            if 'ethernets' in netcfg:
                for interface_name, interface_config in netcfg['ethernets'].items():
                    set_config_interfaces_v2(config, interface_name, interface_config)
                network_configured = True

    # enable DHCPv4 on eth0 if network still not configured
    if network_configured is False:
        set_config_dhcp(config)

    # enable SSH service
    set_config_ssh(config)
    # configure hostname
    if fqdn:
        set_config_hostname(config, fqdn)
    elif hostname:
        set_config_hostname(config, hostname)
    else:
        set_config_hostname(config, 'vyos')

    # save a new configuration file
    try:
        with open(cfg_file_name, 'w') as f:
            f.write(config.to_string())
            logger.debug("Configuration file saved: {}".format(cfg_file_name))
    except Exception as e:
        logger.error("Failed to write configs into file {}: {}".format(cfg_file_name, e))
