# VyOS unattended installation module
# Copyright (C) 2023 VyOS Inc.

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.
"""VyOS Installation: Install VyOS unattendedly"""

from logging import Logger
from json import loads as json_loads
from pathlib import Path
from shutil import copy, rmtree
from shlex import split as shlex_split
from subprocess import run
from textwrap import dedent
from os import sync

from psutil import disk_partitions

from cloudinit import log as logging
from cloudinit.cloud import Cloud
from cloudinit.util import get_cfg_by_path

MODULE_DESCRIPTION = """\
This module installs VyOS unattendedly.
"""

LOG = logging.getLogger(__name__)

# VyOS definitions
VERSION_FILE = '/usr/share/vyos/version.json'
# a reserved space: 2MB for header, 1 MB for BIOS partition, 256 MB for EFI
CONST_RESERVED_SPACE: int = (2 + 1 + 256) * 1024**2

# define directories and paths
DIR_INSTALLATION: str = '/mnt/installation'
DIR_DST_ROOT: str = f'{DIR_INSTALLATION}/disk_dst'
DIR_KERNEL_SRC: str = '/boot/'
FILE_ROOTFS_SRC: str = '/usr/lib/live/mount/medium/live/filesystem.squashfs'


def get_version() -> str:
    """Get running VyOS version id
    Returns:
        str: version id
    """
    version_file: str = Path(VERSION_FILE).read_text()
    version_data = json_loads(version_file)

    return version_data.get('version', 'version_unknown')


def disk_cleanup(drive_path: str) -> None:
    """Clean up disk partition table (MBR and GPT)
    Zeroize primary and secondary headers - first and last 17408 bytes
    (512 bytes * 34 LBA) on a drive
    Args:
        drive_path (str): path to a drive that needs to be cleaned
    """
    run(shlex_split(f'sgdisk -Z {drive_path}'))


def parttable_create(drive_path: str, root_size: int) -> None:
    """Create a hybrid MBR/GPT partition table
    0-2047 first sectors are free
    2048-4095 sectors - BIOS Boot Partition
    4096 + 256 MB - EFI system partition
    Everything else till the end of a drive - Linux partition
    Args:
        drive_path (str): path to a drive
    """
    if not root_size:
        root_size_text: str = '0'
    else:
        root_size_text: str = f'+{str(root_size)}K'
    command: str = f'sgdisk -a1 -n1:2048:4095 -t1:EF02 -n2:4096:+256M \
        -t2:EF00 -n3:0:{root_size_text} -t3:8300 {drive_path}'

    run(shlex_split(command))
    # update partitons in kernel
    run(shlex_split(f'partx -u {drive_path}'))
    sync()


def filesystem_create(partition: str, fstype: str) -> None:
    """Create a filesystem on a partition
    Args:
        partition (str): path to a partition (for example: '/dev/sda1')
        fstype (str): filesystem type ('efi' or 'ext4')
    """
    if fstype == 'efi':
        command = 'mkfs -t fat -n EFI'
        run(shlex_split(f'{command} {partition}'))
    if fstype == 'ext4':
        command = 'mkfs -t ext4 -L persistence'
        run(shlex_split(f'{command} {partition}'))


def partition_mount(partition: str,
                    path: str,
                    fsype: str = '',
                    overlay_params: 'dict[str, str]' = {}) -> None:
    """Mount a partition into a path
    Args:
        partition (str): path to a partition (for example: '/dev/sda1')
        path (str): a path where to mount
        fsype (str): optionally, set fstype ('squashfs', 'overlay', 'iso9660')
        overlay_params (dict): optionally, set overlay parameters.
        Defaults to None.
    """
    if fsype in ['squashfs', 'iso9660']:
        command: str = f'mount -o loop,ro -t {fsype} {partition} {path}'
    if fsype == 'overlay' and overlay_params:
        command: str = f'mount -t overlay -o noatime,\
            upperdir={overlay_params["upperdir"]},\
            lowerdir={overlay_params["lowerdir"]},\
            workdir={overlay_params["workdir"]} overlay {path}'

    else:
        command = f'mount {partition} {path}'

    run(shlex_split(command))


def partition_umount(partition: str = '', path: str = '') -> None:
    """Umount a partition by a partition name or a path
    Args:
        partition (str): path to a partition (for example: '/dev/sda1')
        path (str): a path where a partition is mounted
    """
    if partition:
        command: str = f'umount {partition}'
        run(shlex_split(command))
    if path:
        command = f'umount {path}'
        run(shlex_split(command))


def disks_size() -> 'dict[str, int]':
    """Get a dictionary with physical disks and their sizes
    Returns:
        dict[str, int]: a dictionary with name: size mapping
    """
    disks_size: dict[str, int] = {}
    lsblk: str = run(shlex_split('lsblk -Jbp'),
                     capture_output=True).stdout.decode()
    blk_list = json_loads(lsblk)
    for device in blk_list.get('blockdevices'):
        if device['type'] == 'disk':
            disks_size.update({device['name']: device['size']})
    return disks_size


def find_disk() -> 'tuple[str, int]':
    """Find a target disk for installation
    Returns:
        tuple[str, int]: disk name and size in bytes
    """
    # check for available disks
    disks_available: dict[str, int] = disks_size()
    if not disks_available:
        return '', 0

    for disk_name, disk_size in disks_available.copy().items():
        # minimum 2 GB
        if disk_size > 2147483648:
            return disk_name, disk_size

    return '', 0


def prepare_tmp_disr() -> None:
    """Create temporary directories for installation
    """
    dirpath = Path(DIR_DST_ROOT)
    dirpath.mkdir(mode=0o755, parents=True)


def cleanup(mounts: 'list[str]' = [], remove_items: 'list[str]' = []) -> None:
    """Clean up after installation
    Args:
        mounts (list[str], optional): List of mounts to unmount.
        Defaults to [].
        remove_items (list[str], optional): List of files or directories
        to remove. Defaults to [].
    """
    # clean up installation directory by default
    mounts_all = disk_partitions(all=True)
    for mounted_device in mounts_all:
        if mounted_device.mountpoint.startswith(DIR_INSTALLATION) and not (
                mounted_device.device in mounts or
                mounted_device.mountpoint in mounts):
            mounts.append(mounted_device.mountpoint)
    # add installation dir to cleanup list
    if DIR_INSTALLATION not in remove_items:
        remove_items.append(DIR_INSTALLATION)

    if mounts:
        for mountpoint in mounts:
            partition_umount(mountpoint)
    if remove_items:
        for remove_item in remove_items:
            if Path(remove_item).exists():
                if Path(remove_item).is_file():
                    Path(remove_item).unlink()
                if Path(remove_item).is_dir():
                    rmtree(remove_item)


def grub_install(drive_path: str, boot_dir: str, efi_dir: str) -> None:
    """Install GRUB for both BIOS and EFI modes (hybrid boot)
    Args:
        drive_path (str): path to a drive where GRUB must be installed
        boot_dir (str): a path to '/boot' directory
        efi_dir (str): a path to '/boot/efi' directory
    """
    commands: list[str] = [
        f'grub-install --no-floppy --target=i386-pc \
            --boot-directory={boot_dir} {drive_path} --force',
        f'grub-install --no-floppy --recheck --target=x86_64-efi \
            --force-extra-removable --boot-directory={boot_dir} \
            --efi-directory={efi_dir} --bootloader-id="VyOS" \
            --no-uefi-secure-boot'
    ]
    for command in commands:
        run(shlex_split(command))


def grub_configure(grub_dir: str, vyos_version: str,
                   boot_params: 'dict[str, str]') -> None:
    """Configure GRUB

    Args:
        grub_dir (str): path to GRUB folder
        vyos_version (str): VyOS version id
        boot_params (dict[str, str]): boot parameters
    """
    if boot_params['console_type'] == 'kvm':
        default_boot = 0
    elif boot_params['console_type'] == 'serial':
        default_boot = 1
    grub_cfg_content: str = dedent(f'''
    # load EFI video modules
    if [ "${{grub_platform}}" == "efi" ]; then
    insmod efi_gop
    insmod efi_uga
    fi

    set default={default_boot}
    set timeout=5
    serial --unit={boot_params['serial_console_num']} --speed={boot_params['serial_console_speed']}
    terminal_output --append serial console
    terminal_input --append serial console

    menuentry "VyOS { vyos_version } (KVM console)" {{
        linux /boot/{ vyos_version }/vmlinuz boot=live rootdelay=5 noautologin net.ifnames=0 biosdevname=0 vyos-union=/boot/{ vyos_version } console=tty0
        initrd /boot/{ vyos_version }/initrd.img
    }}

    menuentry "VyOS { vyos_version } (Serial console)" {{
        linux /boot/{ vyos_version }/vmlinuz boot=live rootdelay=5 noautologin net.ifnames=0 biosdevname=0 vyos-union=/boot/{ vyos_version } console=ttyS{boot_params['serial_console_num']},{boot_params['serial_console_speed']}
        initrd /boot/{ vyos_version }/initrd.img
    }}

    menuentry "VyOS { vyos_version } - password reset (KVM console)" {{
        linux /boot/{ vyos_version }/vmlinuz boot=live rootdelay=5 noautologin net.ifnames=0 biosdevname=0 vyos-union=/boot/{ vyos_version } console=tty0 init=/opt/vyatta/sbin/standalone_root_pw_reset
        initrd /boot/{ vyos_version }/initrd.img
    }}

    menuentry "VyOS { vyos_version } - password reset (Serial console)" {{
        linux /boot/{ vyos_version }/vmlinuz boot=live rootdelay=5 noautologin net.ifnames=0 biosdevname=0 vyos-union=/boot/{ vyos_version } console=ttyS{boot_params['serial_console_num']},{boot_params['serial_console_speed']} init=/opt/vyatta/sbin/standalone_root_pw_reset
        initrd /boot/{ vyos_version }/initrd.img
    }}
    ''')

    grub_cfg_file = Path(f'{grub_dir}/grub.cfg')
    grub_cfg_file.write_text(grub_cfg_content)


def handle(name: str, cfg: dict, cloud: Cloud, _: Logger, args: list) -> None:
    # check if installation is activated in config
    install_activated: bool = get_cfg_by_path(cfg, 'vyos_install/activated',
                                              False)
    if not install_activated:
        LOG.info('Installation is not activated in configuration')
        return

    # Find a version name to use later
    image_name: str = get_version()
    LOG.debug(f'version to be installed: {image_name}')

    # define target drive
    install_target, target_size = find_disk()
    # add prefix to partitions
    part_prefix: str = ''
    for dev_type in ['nvme', 'mmcblk']:
        if dev_type in install_target:
            part_prefix = 'p'
    LOG.info(
        f'system will be installed to {install_target} ({target_size} bytes)')

    # define target rootfs size in KB (smallest unit acceptable by sgdisk)
    rootfs_size: int = (target_size - CONST_RESERVED_SPACE) // 1024
    LOG.info(f'rootfs size: {rootfs_size} bytes')

    # create partitions
    disk_cleanup(install_target)
    LOG.info('disk cleaned')
    parttable_create(install_target, rootfs_size)
    LOG.info('partitin table created')
    filesystem_create(f'{install_target}{part_prefix}2', 'efi')
    LOG.info('efi filesystem created')
    filesystem_create(f'{install_target}{part_prefix}3', 'ext4')
    LOG.info('ext4 filesystem created')

    # create directiroes for installation media
    prepare_tmp_disr()
    LOG.info('prepared temporary folders for installation')

    # mount target filesystem and create required dirs inside
    partition_mount(f'{install_target}{part_prefix}3', DIR_DST_ROOT)
    LOG.info(
        f'partiton {install_target}{part_prefix}3 mouted to {DIR_DST_ROOT}')
    Path(f'{DIR_DST_ROOT}/boot/efi').mkdir(parents=True)
    partition_mount(f'{install_target}{part_prefix}2',
                    f'{DIR_DST_ROOT}/boot/efi')
    LOG.info(
        f'partiton {install_target}{part_prefix}2 mouted to {DIR_DST_ROOT}/boot/efi'
    )

    # copy config
    # a config dir. It is the deepest one, so the comand will
    # create all the rest in a single step
    target_config_dir: str = f'{DIR_DST_ROOT}/boot/{image_name}/rw/opt/vyatta/etc/'
    Path(target_config_dir).mkdir(parents=True)
    # we must use Linux cp command, because Python cannot preserve ownership
    run(['cp', '-pr', '/opt/vyatta/etc/config', target_config_dir])
    LOG.info('configuration copied from running system')

    # create a persistence.conf
    Path(f'{DIR_DST_ROOT}/persistence.conf').write_text('/ union\n')
    LOG.info('root filesystem marked as persistent')

    # copy system image and kernel files
    for file in Path(DIR_KERNEL_SRC).iterdir():
        if file.is_file():
            copy(file, f'{DIR_DST_ROOT}/boot/{image_name}/')
            LOG.info(f'{file} installed into {DIR_DST_ROOT}/boot/{image_name}/')
    copy(FILE_ROOTFS_SRC,
         f'{DIR_DST_ROOT}/boot/{image_name}/{image_name}.squashfs')
    LOG.info(
        f'{FILE_ROOTFS_SRC} installed into {DIR_DST_ROOT}/boot/{image_name}/{image_name}.squashfs'
    )

    # install GRUB
    grub_install(install_target, f'{DIR_DST_ROOT}/boot/',
                 f'{DIR_DST_ROOT}/boot/efi')
    LOG.info('GRUB installed')

    # configure GRUB
    boot_params: dict[str, str] = {
        'console_type':
            get_cfg_by_path(cfg, 'vyos_install/boot_params/console_type',
                            'kvm'),
        'serial_console_num':
            get_cfg_by_path(cfg, 'vyos_install/boot_params/serial_console_num',
                            '0'),
        'serial_console_speed':
            get_cfg_by_path(cfg,
                            'vyos_install/boot_params/serial_console_speed',
                            '9600')
    }
    grub_configure(f'{DIR_DST_ROOT}/boot/grub', image_name, boot_params)
    LOG.info('GRUB configured')

    # check if we need to disable Cloud-init
    if get_cfg_by_path(cfg, 'vyos_install/ci_disable', False):
        LOG.info('Disabling Cloud-init')
        Path(f'{DIR_DST_ROOT}/boot/{image_name}/rw/etc/cloud').mkdir(
            parents=True)
        Path(
            f'{DIR_DST_ROOT}/boot/{image_name}/rw/etc/cloud/cloud-init.disabled'
        ).touch()

    # umount filesystems and remove temporary files
    cleanup(
        [f'{install_target}{part_prefix}2', f'{install_target}{part_prefix}3'],
        ['/mnt/installation'])
    LOG.info('temporary resources freed up')

    # check if we need to reboot
    if get_cfg_by_path(cfg, 'vyos_install/post_reboot', False):
        LOG.warn('Adding reboot trigger to postconfig script')
        script_file = Path(
            '/opt/vyatta/etc/config/scripts/vyos-postconfig-bootup.script')
        script_file_data: str = script_file.read_text() + '\nsystemctl reboot\n'
        script_file.write_text(script_file_data)

    # sync just in case
    sync()
