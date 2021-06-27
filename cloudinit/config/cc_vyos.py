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

import re
import ipaddress
from os import path
from uuid import uuid4
from cloudinit import log as logging
from cloudinit.ssh_util import AuthKeyLineParser
from cloudinit.distros import ug_util
from cloudinit.settings import PER_INSTANCE
from cloudinit.sources import INSTANCE_JSON_FILE
from cloudinit.stages import Init
from cloudinit.util import load_file, load_json, get_hostname_fqdn
from cloudinit.sources.DataSourceOVF import get_properties as ovf_get_properties
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
def set_pass_login(config, user, password):
    # check if a password string is a hash or a plaintext password
    # the regex from Cloud-init documentation, so we should trust it for this purpose
    encrypted_pass = re.match(r'\$(1|2a|2y|5|6)(\$.+){2}', password)
    if encrypted_pass:
        logger.debug("Configuring encrypted password for: {}".format(user))
        config.set(['system', 'login', 'user', user, 'authentication', 'encrypted-password'], value=password, replace=True)
    else:
        logger.debug("Configuring plaintext password password for: {}".format(user))
        config.set(['system', 'login', 'user', user, 'authentication', 'plaintext-password'], value=password, replace=True)

    config.set_tag(['system', 'login', 'user'])

    # Return True if credentials added
    return True


# configure user account with ssh key
def set_ssh_login(config, user, key_string):
    ssh_parser = AuthKeyLineParser()
    key_parsed = ssh_parser.parse(key_string)
    logger.debug("Parsed SSH public key: type: {}, base64: \"{}\", comment: {}, options: {}".format(key_parsed.keytype, key_parsed.base64, key_parsed.comment, key_parsed.options))

    if key_parsed.keytype not in ['ssh-dss', 'ssh-rsa', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ssh-ed25519', 'ecdsa-sha2-nistp521']:
        logger.error("Key type {} not supported.".format(key_parsed.keytype))
        return False

    if not key_parsed.base64:
        logger.error("Key base64 not defined, wrong ssh key format.")
        return False

    if not key_parsed.comment:
        key_parsed.comment = "cloud-init-{}".format(uuid4())

    config.set(['system', 'login', 'user', user, 'authentication', 'public-keys', key_parsed.comment, 'key'], value=key_parsed.base64, replace=True)
    config.set(['system', 'login', 'user', user, 'authentication', 'public-keys', key_parsed.comment, 'type'], value=key_parsed.keytype, replace=True)
    if key_parsed.options:
        config.set(['system', 'login', 'user', user, 'authentication', 'public-keys', key_parsed.comment, 'options'], value=key_parsed.options, replace=True)
    config.set_tag(['system', 'login', 'user'])
    config.set_tag(['system', 'login', 'user', user, 'authentication', 'public-keys'])
    logger.debug("Configured SSH public key for user: {}".format(user))

    # Return True if credentials added
    return True


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
        logger.warning("Hostname/domain was filtered: {} -> {}".format(hostname, filtered_hostname))
    # return safe to apply host-name value
    return filtered_hostname


# configure system parameters from OVF template
def set_config_ovf(config, ovf_environment):
    logger.debug("Applying configuration from an OVF template")

    # Check for 'null' values and replace them by the 'None'
    # this make the rest of the code easier
    for (ovf_property_key, ovf_property_value) in ovf_environment.items():
        if ovf_property_value == 'null':
            ovf_environment[ovf_property_key] = None

    # get all variables required for configuration
    ip_address = ovf_environment['ip0']
    ip_mask = ovf_environment['netmask0']
    gateway = ovf_environment['gateway']
    dns_string = ovf_environment['DNS']
    ntp_string = ovf_environment['NTP']
    api_key = ovf_environment['APIKEY']
    api_port = ovf_environment['APIPORT']
    api_debug = ovf_environment['APIDEBUG']

    # Configure an interface and default route
    if ip_address and ip_mask and gateway:
        ip_address_cidr = ipaddress.ip_interface("{}/{}".format(ip_address, ip_mask.replace('/', ''))).with_prefixlen
        logger.debug("Configuring the IP address on the eth0 interface: {}".format(ip_address_cidr))
        set_ipaddress(config, 'eth0', ip_address_cidr)

        logger.debug("Configuring default route via: {}".format(gateway))
        config.set(['protocols', 'static', 'route', '0.0.0.0/0', 'next-hop'], value=gateway, replace=True)
        config.set_tag(['protocols', 'static', 'route'])
        config.set_tag(['protocols', 'static', 'route', '0.0.0.0/0', 'next-hop'])
    else:
        logger.debug("Configuring a DHCP client on the eth0 interface (fallback from OVF)")
        set_ipaddress(config, 'eth0', 'dhcp')

    # Configure DNS servers
    if dns_string:
        dns_list = list(dns_string.replace(' ', '').split(','))
        for server in dns_list:
            logger.debug("Configuring DNS server: {}".format(server))
            config.set(['system', 'name-server'], value=server, replace=False)

    # Configure NTP servers
    if ntp_string:
        ntp_list = list(ntp_string.replace(' ', '').split(','))
        config.delete(['system', 'ntp'])
        for server in ntp_list:
            logger.debug("Configuring NTP server: {}".format(server))
            config.set(['system', 'ntp', 'server'], value=server, replace=False)
            config.set_tag(['system', 'ntp', 'server'])

    # Configure API
    if api_key:
        logger.debug("Configuring HTTP API key: {}".format(api_key))
        config.set(['service', 'https', 'api', 'keys', 'id', 'cloud-init', 'key'], value=api_key, replace=True)
        config.set_tag(['service', 'https', 'api', 'keys', 'id'])
    if api_key and api_port:
        logger.debug("Configuring HTTP API port: {}".format(api_port))
        config.set(['service', 'https', 'listen-address', '0.0.0.0', 'listen-port'], value=api_port, replace=True)
        config.set_tag(['service', 'https', 'listen-address'])
    if api_key and api_debug != 'False':
        logger.debug("Enabling HTTP API debug")
        config.set(['service', 'https', 'api', 'debug'], replace=True)


# get an IP address type
def get_ip_type(address):
    addr_type = None
    if address in ['dhcp', 'dhcpv6']:
        addr_type = address
    else:
        try:
            ip_version = ipaddress.ip_interface(address).version
            if ip_version == 4:
                addr_type = 'ipv4'
            if ip_version == 6:
                addr_type = 'ipv6'
        except Exception as err:
            logger.error("Unable to detect IP address type: {}".format(err))
    logger.debug("IP address {} have type: {}".format(address, addr_type))
    return addr_type


# configure IP address for interface
def set_ipaddress(config, iface, address):
    # detect an IP address type
    addr_type = get_ip_type(address)
    if not addr_type:
        logger.error("Unable to configure the IP address: {}".format(address))
        return

    # check a current configuration of an interface
    if config.exists(['interfaces', 'ethernet', iface, 'address']):
        current_addresses = config.return_values(['interfaces', 'ethernet', iface, 'address'])
        logger.debug("IP address for interface {} already configured: {}".format(iface, current_addresses))
        # check if currently configured addresses can be used with new one
        incompatible_addresses = []
        for current_address in current_addresses:
            # dhcp cannot be used with static IP address at the same time
            if ((addr_type == 'dhcp' and get_ip_type(current_address) == 'ipv4') or
                    (addr_type == 'ipv4' and get_ip_type(current_address) == 'dhcp') or
                    (addr_type == 'dhcpv6' and get_ip_type(current_address) == 'ipv6') or
                    (addr_type == 'ipv6' and get_ip_type(current_address) == 'dhcpv6')):
                incompatible_addresses.append(current_address)
        # inform about error and skip configuration
        if incompatible_addresses:
            logger.error("IP address {} cannot be configured, because it conflicts with already exists: {}".format(address, incompatible_addresses))
            return

    # configure address
    logger.debug("Configuring IP address {} on interface {}".format(address, iface))
    config.set(['interfaces', 'ethernet', iface, 'address'], value=address, replace=False)
    config.set_tag(['interfaces', 'ethernet'])


# configure interface from networking config version 1
def set_config_interfaces_v1(config, iface_config):
    logger.debug("Configuring network using Cloud-init networking config version 1")
    # configure physical interfaces
    if iface_config['type'] == 'physical':
        iface_name = iface_config['name']

        # configre MAC
        if 'mac_address' in iface_config:
            logger.debug("Setting MAC for {}: {}".format(iface_name, iface_config['mac_address']))
            config.set(['interfaces', 'ethernet', iface_name, 'hw-id'], value=iface_config['mac_address'], replace=True)
            config.set_tag(['interfaces', 'ethernet'])

        # configre MTU
        if 'mtu' in iface_config:
            logger.debug("Setting MTU for {}: {}".format(iface_name, iface_config['mtu']))
            config.set(['interfaces', 'ethernet', iface_name, 'mtu'], value=iface_config['mtu'], replace=True)
            config.set_tag(['interfaces', 'ethernet'])

        # configure subnets
        if 'subnets' in iface_config:
            for subnet in iface_config['subnets']:
                # configure DHCP client
                if subnet['type'] in ['dhcp', 'dhcp4', 'dhcp6']:
                    if subnet['type'] == 'dhcp6':
                        set_ipaddress(config, iface_name, 'dhcpv6')
                    else:
                        set_ipaddress(config, iface_name, 'dhcp')

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
                        if ip_version == 4 and ip_address != '0.0.0.0':
                            if '/' in subnet['address']:
                                ip_static_addr = ip_interface.compressed
                            else:
                                ip_static_addr = ipaddress.IPv4Interface('{}/{}'.format(ip_address, subnet['netmask'])).compressed
                        # format IPv6
                        if ip_version == 6:
                            ip_static_addr = ip_interface.compressed
                        # apply to the configuration
                        if ip_static_addr:
                            set_ipaddress(config, iface_name, ip_static_addr)
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
                                    config.set_tag(['protocols', 'static', 'route', ip_network.compressed, 'next-hop'])
                                if ip_network.version == 6:
                                    logger.debug("Configuring IPv6 route on {}: {} via {}".format(iface_name, ip_network.compressed, item['gateway']))
                                    config.set(['protocols', 'static', 'route6', ip_network.compressed, 'next-hop'], value=item['gateway'], replace=True)
                                    config.set_tag(['protocols', 'static', 'route6'])
                                    config.set_tag(['protocols', 'static', 'route6', ip_network.compressed, 'next-hop'])
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
                            config.set(['system', 'domain-search', 'domain'], value=item, replace=False)

    # configure nameservers
    if iface_config['type'] == 'nameserver':
        for item in iface_config['address']:
            logger.debug("Configuring DNS nameserver: {}".format(item))
            config.set(['system', 'name-server'], value=item, replace=False)

        if 'search' in iface_config:
            for item in iface_config['search']:
                logger.debug("Configuring DNS search domain: {}".format(item))
                config.set(['system', 'domain-search', 'domain'], value=item, replace=False)

    # configure routes
    if iface_config['type'] == 'route':
        try:
            ip_network = ipaddress.ip_network(iface_config['destination'])
            if ip_network.version == 4:
                logger.debug("Configuring IPv4 route: {} via {}".format(ip_network.compressed, iface_config['gateway']))
                config.set(['protocols', 'static', 'route', ip_network.compressed, 'next-hop'], value=iface_config['gateway'], replace=True)
                config.set_tag(['protocols', 'static', 'route'])
                config.set_tag(['protocols', 'static', 'route', ip_network.compressed, 'next-hop'])
                if 'metric' in iface_config:
                    config.set(['protocols', 'static', 'route', ip_network.compressed, 'next-hop', iface_config['gateway'], 'distance'], value=iface_config['metric'], replace=True)
            if ip_network.version == 6:
                logger.debug("Configuring IPv6 route: {} via {}".format(ip_network.compressed, iface_config['gateway']))
                config.set(['protocols', 'static', 'route6', ip_network.compressed, 'next-hop'], value=iface_config['gateway'], replace=True)
                config.set_tag(['protocols', 'static', 'route6'])
                config.set_tag(['protocols', 'static', 'route6', ip_network.compressed, 'next-hop'])
                if 'metric' in iface_config:
                    config.set(['protocols', 'static', 'route6', ip_network.compressed, 'next-hop', iface_config['gateway'], 'distance'], value=iface_config['metric'], replace=True)
        except Exception as err:
            logger.error("Impossible to detect IP protocol version: {}".format(err))


# configure interface from networking config version 2
def set_config_interfaces_v2(config, iface_name, iface_config):
    logger.debug("Configuring network using Cloud-init networking config version 2")

    # configure MAC
    if 'match' in iface_config and 'macaddress' in iface_config['match']:
        logger.debug("Setting MAC for {}: {}".format(iface_name, iface_config['match']['macaddress']))
        config.set(['interfaces', 'ethernet', iface_name, 'hw-id'], value=iface_config['match']['macaddress'], replace=True)
        config.set_tag(['interfaces', 'ethernet'])

    # configure DHCP client
    if 'dhcp4' in iface_config:
        if iface_config['dhcp4'] is True:
            set_ipaddress(config, iface_name, 'dhcp')
    if 'dhcp6' in iface_config:
        if iface_config['dhcp6'] is True:
            set_ipaddress(config, iface_name, 'dhcpv6')

    # configure static addresses
    if 'addresses' in iface_config:
        for item in iface_config['addresses']:
            set_ipaddress(config, iface_name, item)

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

    # configure MTU
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
                config.set(['system', 'domain-search', 'domain'], value=item, replace=False)
        if 'addresses' in iface_config['nameservers']:
            for item in iface_config['nameservers']['addresses']:
                logger.debug("Configuring DNS nameserver for {}: {}".format(iface_name, item))
                config.set(['system', 'name-server'], value=item, replace=False)


# configure DHCP client for eth0 interface (fallback)
def set_config_dhcp(config):
    logger.debug("Configuring DHCPv4 on eth0 interface (fallback)")
    set_ipaddress(config, 'eth0', 'dhcp')


# configure SSH server service
def set_config_ssh(config):
    logger.debug("Configuring SSH service")
    config.set(['service', 'ssh'], replace=True)
    config.set(['service', 'ssh', 'port'], value='22', replace=True)
    config.set(['service', 'ssh', 'client-keepalive-interval'], value='180', replace=True)


# configure hostname
def set_config_hostname(config, hostname, fqdn):
    if hostname:
        logger.debug("Configuring hostname to: {}".format(hostname_filter(hostname)))
        config.set(['system', 'host-name'], value=hostname_filter(hostname), replace=True)
    if fqdn:
        try:
            domain_name = fqdn.partition("{}.".format(hostname))[2]
            if domain_name:
                logger.debug("Configuring domain-name to: {}".format(hostname_filter(domain_name)))
                config.set(['system', 'domain-name'], value=hostname_filter(domain_name), replace=True)
        except Exception as err:
            logger.error("Failed to configure domain-name: {}".format(err))


# main config handler
def handle(name, cfg, cloud, log, _args):
    logger.debug("Cloud-init config: {}".format(cfg))
    # fetch all required data from Cloud-init
    # Datasource name
    dsname = cloud.datasource.dsname
    logger.debug("Datasource: {}".format(dsname))
    # Metadata (datasource specific)
    metadata_ds = cloud.datasource.metadata
    logger.debug("Meta-Data ds: {}".format(metadata_ds))
    # Metadata in stable v1 format (the same structure for all datasources)
    instance_data_json = load_json(load_file("{}/{}".format(cloud.datasource.paths.run_dir, INSTANCE_JSON_FILE)))
    metadata_v1 = instance_data_json.get('v1')
    logger.debug("Meta-Data v1: {}".format(metadata_v1))
    # User-Data
    userdata = cloud.datasource.userdata
    logger.debug("User-Data: {}".format(userdata))
    # Vendor-Data
    vendordata = cloud.datasource.vendordata
    logger.debug("Vendor-Data: {}".format(vendordata))
    # Network-config
    netcfg = cloud.datasource.network_config
    if netcfg:
        netcfg_src = dsname
    else:
        init_stage = Init()
        (netcfg, netcfg_src) = init_stage._find_networking_config()
    logger.debug("Network-config: {}".format(netcfg))
    logger.debug("Network-config source: {}".format(netcfg_src))
    # Hostname with FQDN (if exist)
    (hostname, fqdn) = get_hostname_fqdn(cfg, cloud, metadata_only=True)
    logger.debug("Hostname: {}, FQDN: {}".format(hostname, fqdn))
    # Get users list
    (users, _) = ug_util.normalize_users_groups(cfg, cloud.distro)
    logger.debug("Users: {}".format(users))
    (default_user, default_user_config) = ug_util.extract_default(users)
    logger.debug("Default user: {}".format(default_user))
    # Get OVF properties
    if 'OVF' in dsname:
        ovf_environment = ovf_get_properties(cloud.datasource.environment)
        logger.debug("OVF environment: {}".format(ovf_environment))

    # VyOS configuration file selection
    cfg_file_name = '/opt/vyatta/etc/config/config.boot'
    bak_file_name = '/opt/vyatta/etc/config.boot.default'

    # open configuration file
    if not path.exists(cfg_file_name):
        file_name = bak_file_name
    else:
        file_name = cfg_file_name

    logger.debug("Using configuration file: {}".format(file_name))
    with open(file_name, 'r') as f:
        config_file = f.read()
    config = ConfigTree(config_file)

    # Initialization of variables
    DEFAULT_VYOS_USER = 'vyos'
    DEFAULT_VYOS_PASSWORD = 'vyos'
    logins_configured = False
    network_configured = False

    # configure system logins
    # Prepare SSH public keys for default user, to be sure that global keys applied to the default account (if it exist)
    # If the ssh key is left emty on an OVA deploy the OVF datastore passes an empty string which generates an invalid key error. 
    # Set the ssh_keys variable from the metadata_v1['public_ssh_keys'] checked for empty strings.
    ssh_keys = [key for key in metadata_v1['public_ssh_keys'] if key ]
    # append SSH keys from cloud-config
    ssh_keys.extend(cfg.get('ssh_authorized_keys', []))
    # Configure authentication for default user account
    if default_user:
        # key-based
        for ssh_key in ssh_keys:
            if set_ssh_login(config, default_user, ssh_key):
                logins_configured = True
        # password-based
        password = cfg.get('password')
        if password:
            if set_pass_login(config, default_user, password):
                logins_configured = True

    # Configure all users accounts
    for user, user_cfg in users.items():
        # Configure password-based authentication
        password = user_cfg.get('passwd')
        if password and password != '':
            if set_pass_login(config, user, password):
                logins_configured = True

        # Configure key-based authentication
        for ssh_key in user_cfg.get('ssh_authorized_keys', []):
            if set_ssh_login(config, user, ssh_key):
                logins_configured = True

    # Create a fallback user if there was no others
    if not logins_configured:
        logger.debug("Adding fallback user: {}".format(DEFAULT_VYOS_USER))
        set_pass_login(config, DEFAULT_VYOS_USER, DEFAULT_VYOS_PASSWORD)

    # apply settings from OVF template
    if 'OVF' in dsname:
        set_config_ovf(config, ovf_environment)
        # Empty hostname option may be interpreted as 'null' string by some hypervisors
        # we need to replace it to the empty value to process it later properly
        if hostname and hostname == 'null':
            hostname = None
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
    # configure hostname and domain
    if hostname:
        set_config_hostname(config, hostname, fqdn)
    else:
        set_config_hostname(config, 'vyos', None)

    # save a new configuration file
    try:
        with open(cfg_file_name, 'w') as f:
            f.write(config.to_string())
            logger.debug("Configuration file saved: {}".format(cfg_file_name))
    except Exception as e:
        logger.error("Failed to write configs into file {}: {}".format(cfg_file_name, e))
