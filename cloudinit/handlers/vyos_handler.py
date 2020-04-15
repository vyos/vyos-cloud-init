#part-handler
# Copyright (C) 2020 Sentrium S.L.

from cloudinit import handlers
from cloudinit import log as logging
from cloudinit.settings import (PER_ALWAYS)

# VyOS specific imports
import re
import requests
import subprocess
from pathlib import Path
from os import sync
from yaml import load
# we need to cover followed imports into try/except to pass building tests
try:
    from vyos.configtree import ConfigTree
    from vyos.version import get_version
except Exception as err:
    print("VyOS module was not found: {}".format(err))

# configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class VyOSConfigPartHandler(handlers.Handler):

    # actually, these prefixes do not use, but due to an internal Cloud-init structure we need to define them here
    prefixes = ["#vyos-config-plain", "#vyos-config-notmulti"]

    def __init__(self, paths, **_kwargs):
        handlers.Handler.__init__(self, PER_ALWAYS, version=3)

    # helper: convert line to command
    def string_to_command(self, stringcmd):
        regex_filter = re.compile(r'^set (?P<cmd_path>[^\']+)( \'(?P<cmd_value>.*)\')*$')
        if regex_filter.search(stringcmd):
            # command structure
            command = {
                'cmd_path': regex_filter.search(stringcmd).group('cmd_path').split(),
                'cmd_value': regex_filter.search(stringcmd).group('cmd_value')
            }
            return command
        else:
            return None

    # get list of all tag nodes
    def get_tag_nodes(self):
        try:
            logger.debug("Searching for tag nodes in configuration templates")
            tags_nodes = []
            templates_dir = '/opt/vyatta/share/vyatta-cfg/templates/'
            tags_path = Path(templates_dir).rglob('node.tag')
            for tag_path in tags_path:
                current_tag_path = tag_path.relative_to(templates_dir).parent.parts
                tags_nodes.append(current_tag_path)
            return tags_nodes
        except Exception as err:
            logger.error("Failed to find tag nodes: {}".format(err))

    # helper: check if the node is tag or not
    def is_tag_node(self, node_path, tag_nodes):
        match = False
        for tag_node in tag_nodes:
            if len(tag_node) == len(node_path):
                for element_id in list(range(len(node_path))):
                    if not (node_path[element_id] == tag_node[element_id] or tag_node[element_id] == 'node.tag'):
                        break
                    elif (node_path[element_id] == tag_node[element_id] or tag_node[element_id] == 'node.tag') and element_id == len(node_path) - 1:
                        match = True
            if match is True:
                break
        if match is True:
            logger.debug("Node {} is a tag node".format(node_path))
            return True
        else:
            logger.debug("Node {} is not a tag node".format(node_path))
            return False

    # helper: mark nodes as tag, if this is necessary
    def mark_tag(self, config, node_path, tag_nodes):
        current_node_path = []
        for current_node in node_path:
            current_node_path.append(current_node)
            if self.is_tag_node(current_node_path, tag_nodes):
                logger.debug("Marking node as tag: \"{}\"".format(current_node_path))
                config.set_tag(current_node_path)

    # get payload from URL
    def download_payload(self, payload):
        # try to download from URL
        try:
            logger.info("Trying to fetch payload from URL: {}".format(payload))
            return requests.get(payload).text
        # return raw data if this was not URL
        except Exception as err:
            logger.error("Failed to downloads payload from URL: {}".format(err))

    # write file
    def write_file(self, file_path, content):
        try:
            with open(file_path, 'w') as f:
                f.write(content)
            logger.info("File saved: {}".format(file_path))
        except Exception as err:
            logger.error("Failed to save file: {}".format(err))

    # check what kind of user-data payload is - config file, commands list, YAML or URL
    def check_payload_format(self, payload):
        # prepare regex for parsing
        regex_url = re.compile(r'https?://[\w\.\:]+/.*$')
        regex_cmdlist = re.compile(r'^set ([^\']+)( \'(.*)\')*')
        regex_cmdfile = re.compile(r'^[\w-]+ {.*')
        regex_yaml = re.compile(r'^[\w-]+: .*$', re.MULTILINE)
        regex_test_plain = re.compile(r'^Just text$')
        regex_test_multi = re.compile(r'^arbitrary text$', re.MULTILINE)

        if regex_cmdfile.search(payload.strip()):
            # try to parse as configuration file
            try:
                payload_config = ConfigTree(payload)
                logger.info("Parsing User-Data payload as VyOS configuration file")
                if payload_config:
                    return 'vyos_config_file'
            except Exception as err:
                logger.error("User-Data payload is not valid VyOS configuration file: {}".format(err))
        elif regex_cmdlist.search(payload.strip()):
            logger.info("User-Data payload is VyOS commands list")
            return 'vyos_config_commands'
        elif regex_yaml.search(payload.strip()):
            logger.info("User-Data payload is YAML")
            return 'vyos_config_yaml'
        elif regex_url.search(payload.strip()):
            logger.info("User-Data payload is URL")
            return 'vyos_config_url'
        # tricks to pass building tests
        elif regex_test_plain.search(payload.strip()):
            logger.warning("Unhandled unknown content-type (text/plain)")
        elif regex_test_multi.search(payload.strip()):
            logger.warning("Unhandled non-multipart (text/x-not-multipart) userdata:")
        else:
            logger.error("User-Data payload format cannot be detected")

    # run command and return stdout and status
    def run_command(self, command, stdinput=None):
        try:
            process = subprocess.Popen(command.split(' '), stdout=subprocess.PIPE, stdin=subprocess.PIPE, universal_newlines=True)
            stdout, stderr = process.communicate(stdinput)
            if process.returncode == 0:
                return stdout
            else:
                raise Exception("The command \"{}\" returned status {}. Error: {}".format(command, process.returncode, stderr))
        except Exception as err:
            logger.error("Unable to execute command \"{}\": {}".format(command, err))
            raise

    # install VyOS
    def install_vyos(self, payload):
        try:
            install_config = load(payload)
        except Exception as err:
            logger.error("Unable to load YAML file: {}".format(err))
            return
        try:
            # enable output to the stderr
            from logging import StreamHandler
            logger.addHandler(StreamHandler())

            # define all variables
            vyos_version = get_version()
            if vyos_version.startswith('1.2'):
                vyos_generation = '1.2'
                rootfspath = '/lib/live/mount/medium/live/filesystem.squashfs'
            else:
                vyos_generation = 'other'
                rootfspath = '/usr/lib/live/mount/medium/live/filesystem.squashfs'
            install_drive = install_config['install_drive']
            partition_size = install_config.get('partition_size', '')
            root_drive = '/mnt/wroot'
            root_read = '/mnt/squashfs'
            root_install = '/mnt/inst_root'
            dir_rw = '{}/boot/{}/rw'.format(root_drive, vyos_version)
            dir_work = '{}/boot/{}/work'.format(root_drive, vyos_version)

            # find and prepare drive and partition
            if install_drive == 'auto':
                regex_lsblk = re.compile(r'^(?P<dev_name>\w+) +(?P<dev_size>\d+) +(?P<dev_type>\w+)( +(?P<part_type>[\w-]+))?$')
                drive_list = self.run_command('lsblk --bytes --nodeps --list --noheadings --output KNAME,SIZE,TYPE')
                for device_line in drive_list.splitlines():
                    found = regex_lsblk.search(device_line)
                    if found:
                        if int(found.group('dev_size')) > 2000000000 and found.group('dev_type') == 'disk':
                            install_drive = '/dev/{}'.format(found.group('dev_name'))
                            break
            if install_drive == 'auto':
                logger.error("No suitable drive found for installation")
                return
            logger.debug("Installing to drive: {}".format(install_drive))

            # Detect system type
            if Path('/sys/firmware/efi/').exists():
                sys_type = 'EFI'
                grub_efi = '--force-extra-removable --efi-directory=/boot/efi --bootloader-id=VyOS --no-uefi-secure-boot '
            else:
                sys_type = 'Non-EFI'
                grub_efi = ''
            logger.debug("Detected {} system".format(sys_type))

            # Create partitions
            logger.debug('Clearing current partitions table on {}'.format(install_drive))
            with open(install_drive, 'w+b') as drive:
                drive.seek(0)
                drive.write(b'0' * 17408)
                drive.seek(-17408, 2)
                drive.write(b'0' * 17408)
            sync()
            self.run_command('partprobe {}'.format(install_drive))

            if vyos_generation == '1.2':
                if sys_type == 'EFI':
                    logger.debug('Creating EFI-compatible partitions table on {}'.format(install_drive))
                    self.run_command('sgdisk -n 1:1M:100M {}'.format(install_drive))
                    self.run_command('sgdisk -t 1:EF00 {}'.format(install_drive))
                    self.run_command('sgdisk -n 2::{} {}'.format(partition_size, install_drive))
                else:
                    logger.debug('Creating BIOS-compatible partitions table on {}'.format(install_drive))
                    disk_parts = '3,{},L,*\n'.format(partition_size)
                    self.run_command('sfdisk -q {}'.format(install_drive), disk_parts)
            else:
                if sys_type == 'EFI':
                    logger.debug('Creating EFI-compatible partitions table on {}'.format(install_drive))
                    disk_parts = 'label: gpt\n,100M,U,*\n,{},L'.format(partition_size)
                else:
                    logger.debug('Creating BIOS-compatible partitions table on {}'.format(install_drive))
                    disk_parts = 'label: dos\n,{},L,*\n'.format(partition_size)
                self.run_command('sfdisk -q -w always -W always {}'.format(install_drive), disk_parts)
            # update partitons in kernel
            self.run_command('partprobe {}'.format(install_drive))

            partitions_list = self.run_command('fdisk -l {}'.format(install_drive))
            regex_fdisk = re.compile(r'^(?P<dev_name>/dev/\w+) +(\* +)?(\d+ +)+([\d\.]+\D) +(\d+ +)?(?P<part_type>\w+).*$')
            for partition_line in partitions_list.splitlines():
                found = regex_fdisk.search(partition_line)
                if found:
                    if found.group('part_type') == 'Linux':
                        root_partition = '{}'.format(found.group('dev_name'))
                        logger.debug("Using partition for root: {}".format(root_partition))
                        self.run_command('mkfs -t ext4 -L persistence {}'.format(root_partition))
                    if found.group('part_type') == 'EFI':
                        efi_partition = '{}'.format(found.group('dev_name'))
                        logger.debug("Using partition for EFI: {}".format(efi_partition))
                        self.run_command('mkfs -t fat -n EFI {}'.format(efi_partition))

            # creating directories
            for dir in [root_drive, root_read, root_install]:
                dirpath = Path(dir)
                logger.debug("Creating directory: {}".format(dir))
                dirpath.mkdir(mode=0o755, parents=True)
            # mounting root drive
            logger.debug("Mounting root drive: {}".format(root_drive))
            self.run_command('mount {} {}'.format(root_partition, root_drive))
            for dir in [dir_rw, dir_work]:
                dirpath = Path(dir)
                logger.debug("Creating directory: {}".format(dir))
                dirpath.mkdir(mode=0o755, parents=True)
            if sys_type == 'EFI':
                Path('/boot/efi').mkdir(mode=0o755, parents=True)
                self.run_command('mount {} {}'.format(efi_partition, '/boot/efi'))
            # copy rootfs
            logger.debug("Copying rootfs: {}/boot/{}/{}.squashfs".format(root_drive, vyos_version, vyos_version))
            self.run_command('cp -p {} {}/boot/{}/{}.squashfs'.format(rootfspath, root_drive, vyos_version, vyos_version))
            # get list of other files for boot and copy to the installation boot directory
            boot_files = self.run_command('find /boot -maxdepth 1 -type f -o -type l')
            for file in boot_files.splitlines():
                logger.debug("Copying file: {}".format(file))
                self.run_command('cp -dp {} {}/boot/{}/'.format(file, root_drive, vyos_version))
            # write persistense.conf
            logger.debug("Writing '{}/persistence.conf".format(root_drive))
            self.write_file('{}/persistence.conf'.format(root_drive), '/ union\n')
            # mount new rootfs
            logger.debug("Mounting read-only rootfs: {}".format(root_read))
            self.run_command('mount -o loop,ro -t squashfs {}/boot/{}/{}.squashfs {}'.format(root_drive, vyos_version, vyos_version, root_read))
            logger.debug("Mounting overlay rootfs: {}".format(root_install))
            self.run_command('mount -t overlay -o noatime,upperdir={},lowerdir={},workdir={} overlay {}'.format(dir_rw, root_read, dir_work, root_install))
            # copy configuration
            logger.debug("Copying configuration to: {}/opt/vyatta/etc/config/config.boot".format(root_install))
            self.run_command('cp -p /opt/vyatta/etc/config/config.boot {}/opt/vyatta/etc/config/config.boot'.format(root_install))
            logger.debug("Copying .vyatta_config to: {}/opt/vyatta/etc/config/.vyatta_config".format(root_install))
            self.run_command('cp -p /opt/vyatta/etc/config/.vyatta_config {}/opt/vyatta/etc/config/.vyatta_config'.format(root_install))
            # install grub
            logger.debug("Installing GRUB to {}".format(install_drive))
            self.run_command('grub-install --no-floppy --recheck --root-directory={} {}{}'.format(root_drive, grub_efi, install_drive))
            # configure GRUB
            logger.debug("Configuring GRUB")
            self.run_command('/opt/vyatta/sbin/vyatta-grub-setup -u {} {} '' {}'.format(vyos_version, root_partition, root_drive))
            # unmount all fs
            for dir in [root_install, root_read, root_drive]:
                logger.debug("Unmounting: {}".format(dir))
                self.run_command('umount {}'.format(dir))
            # reboot the system if this was requested by config
            if install_config.get('reboot_after', False) is True:
                logger.info("Rebooting host")
                self.run_command('systemctl reboot')

        except Exception as err:
            logger.error("Unable to install VyOS: {}".format(err))
            return

    def handle_part(self, data, ctype, filename, payload, frequency, headers):
        if ctype == "__begin__":
            logger.info("VyOS configuration handler for Cloud-init is beginning, frequency={}".format(frequency))
            return
        if ctype == "__end__":
            logger.info("VyOS configuration handler for Cloud-initis is ending, frequency={}".format(frequency))
            return

        logger.info("==== received ctype=%s filename=%s ====" % (ctype, filename))

        try:
            # detect payload format
            payload_format = self.check_payload_format(payload)
            if payload_format == 'vyos_config_url':
                # download and replace payload by content from server
                payload = self.download_payload(payload.strip())
                if payload:
                    payload_format = self.check_payload_format(payload)

            # find path for VyOS config
            cfg_file_name = '/opt/vyatta/etc/config/config.boot'
            bak_file_name = '/opt/vyatta/etc/config.boot.default'
            if not Path(cfg_file_name).exists():
                config_file_path = bak_file_name
            else:
                config_file_path = cfg_file_name

            # try to replace configuration file with new one
            if payload_format == 'vyos_config_file':
                self.write_file(config_file_path, payload)
                return

            # use YAML info for installing VyOS
            if payload_format == 'vyos_config_yaml':
                self.install_vyos(payload)
                return

            # apply commands to the current configuration file
            elif payload_format == 'vyos_config_commands':
                # load local configuration file
                try:
                    with open(config_file_path, 'r') as f:
                        config_file_data = f.read()
                    config = ConfigTree(config_file_data)
                    logger.info("Using configuration file: {}".format(config_file_path))
                except Exception as err:
                    logger.error("Failed to load configuration file: {}".format(err))

                try:
                    # get configuration commands
                    config_lines = payload.splitlines()
                    # get all tag nodes. We should do this here and keep the result to avoid multiple command invoking
                    tag_nodes = self.get_tag_nodes()
                    # roll through configration commands
                    for line in config_lines:
                        # convert command to format, appliable to configuration
                        command = self.string_to_command(line)
                        # if conversion is successful, apply the command
                        if command is not None:
                            logger.debug("Configuring command: \"{}\"".format(line))
                            config.set(command['cmd_path'], command['cmd_value'], replace=True)
                            # mark configured nodes as tag, if this is necessary
                            self.mark_tag(config, command['cmd_path'], tag_nodes)
                except Exception as err:
                    logger.error("Failed to configure system: {}".format(err))

                self.write_file(config_file_path, config.to_string())

            # skip configuration change
            else:
                logger.info("No valid configuration provided. Skipping configuration change")
                return

        except Exception as err:
            logger.error("User-Data payload format detection error: {}".format(err))
            return

        logger.info("==== end ctype=%s filename=%s" % (ctype, filename))


# part for using in part-handler mode
handler_version = 2


def list_types():
    # return a list of mime-types that are handled by this module
    return(["text/plain", "text/x-not-multipart"])


def handle_part(data, ctype, filename, payload, frequency):
    # pass to VyOSConfigPartHandler class
    part_handler = VyOSConfigPartHandler(None)
    part_handler.handle_part(data, ctype, filename, payload, frequency, None)
