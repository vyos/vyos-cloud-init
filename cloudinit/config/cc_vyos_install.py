# Copyright (C) 2024 VyOS Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or later as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# This module is used to cleanup ifupdown config that may be left by Cloud-init after its initialization.
# This must be done during each boot to avoid interferring with VyOS CLI config.

import logging
from json import loads as json_loads
from os import sync
from pathlib import Path
from shlex import split as shlex_split
from shutil import copy, rmtree
from subprocess import run

from psutil import disk_partitions

from cloudinit.cloud import Cloud
from cloudinit.settings import PER_INSTANCE
from cloudinit.util import get_cfg_by_path

try:
    from vyos.system import disk, grub, image
    from vyos.template import render
except ImportError as err:
    print(f"The module cannot be imported: {err}")

MODULE_DESCRIPTION = """\
VyOS unattended installation module.
"""

# a reserved space: 2MB for header, 1 MB for BIOS partition, 256 MB for EFI
CONST_RESERVED_SPACE: int = (2 + 1 + 256) * 1024**2
# define directories and paths
DIR_INSTALLATION: str = "/mnt/installation"
DIR_DST_ROOT: str = f"{DIR_INSTALLATION}/disk_dst"
DIR_KERNEL_SRC: str = "/boot/"
FILE_ROOTFS_SRC: str = "/usr/lib/live/mount/medium/live/filesystem.squashfs"

DEFAULT_BOOT_VARS: dict[str, str] = {
    "timeout": "5",
    "console_type": "tty",
    "console_num": "0",
    "console_speed": "115200",
    "bootmode": "normal",
}

LOG = logging.getLogger(__name__)

frequency = PER_INSTANCE


def disks_size() -> "dict[str, int]":
    """Get a dictionary with physical disks and their sizes
    Returns:
        dict[str, int]: a dictionary with name: size mapping
    """
    disks_size: dict[str, int] = {}
    lsblk: str = run(shlex_split("lsblk -Jbp"), capture_output=True).stdout.decode()
    blk_list = json_loads(lsblk)
    for device in blk_list.get("blockdevices"):
        if device["type"] == "disk":
            disks_size.update({device["name"]: device["size"]})
    return disks_size


def find_disk() -> "tuple[str, int]":
    """Find a target disk for installation
    Returns:
        tuple[str, int]: disk name and size in bytes
    """
    # check for available disks
    disks_available: dict[str, int] = disks_size()
    if not disks_available:
        return "", 0

    for disk_name, disk_size in disks_available.copy().items():
        # minimum 2 GB
        if disk_size > 2147483648:
            return disk_name, disk_size

    return "", 0


def prepare_tmp_disr() -> None:
    """Create temporary directories for installation"""
    dirpath = Path(DIR_DST_ROOT)
    dirpath.mkdir(mode=0o755, parents=True)


def cleanup(mounts: list[str] = [], remove_items: list[str] = []) -> None:
    """Clean up after installation

    Args:
        mounts (list[str], optional): List of mounts to unmount.
        Defaults to [].
        remove_items (list[str], optional): List of files or directories
        to remove. Defaults to [].
    """
    LOG.debug("Cleaning up")
    # clean up installation directory by default
    mounts_all = disk_partitions(all=True)
    for mounted_device in mounts_all:
        if mounted_device.mountpoint.startswith(DIR_INSTALLATION) and not (
            mounted_device.device in mounts or mounted_device.mountpoint in mounts
        ):
            mounts.append(mounted_device.mountpoint)
    # add installation dir to cleanup list
    if DIR_INSTALLATION not in remove_items:
        remove_items.append(DIR_INSTALLATION)

    if mounts:
        LOG.debug("Unmounting target filesystems")
        for mountpoint in mounts:
            disk.partition_umount(mountpoint)
        for mountpoint in mounts:
            disk.wait_for_umount(mountpoint)
    if remove_items:
        LOG.debug("Removing temporary files")
        for remove_item in remove_items:
            if Path(remove_item).exists():
                if Path(remove_item).is_file():
                    Path(remove_item).unlink()
                if Path(remove_item).is_dir():
                    rmtree(remove_item, ignore_errors=True)


def setup_grub(root_dir: str, vars: dict[str, str]) -> None:
    """Install GRUB configurations

    Args:
        root_dir (str): a path to the root of target filesystem
    """
    LOG.debug("Installing GRUB configuration files")
    grub_cfg_main = f"{root_dir}/{grub.GRUB_DIR_MAIN}/grub.cfg"
    grub_cfg_vars = f"{root_dir}/{grub.CFG_VYOS_VARS}"
    grub_cfg_modules = f"{root_dir}/{grub.CFG_VYOS_MODULES}"
    grub_cfg_menu = f"{root_dir}/{grub.CFG_VYOS_MENU}"
    grub_cfg_options = f"{root_dir}/{grub.CFG_VYOS_OPTIONS}"

    # create new files
    render(grub_cfg_main, grub.TMPL_GRUB_MAIN, {})
    grub.common_write(root_dir)
    grub.vars_write(grub_cfg_vars, vars)
    grub.modules_write(grub_cfg_modules, [])
    grub.write_cfg_ver(1, root_dir)
    render(grub_cfg_menu, grub.TMPL_GRUB_MENU, {})
    render(grub_cfg_options, grub.TMPL_GRUB_OPTS, {})


def handle(name: str, cfg, cloud: Cloud, log, args: list) -> None:
    LOG.info(f"Running {name} module")
    # check if installation is activated in config
    if not get_cfg_by_path(cfg, "vyos_install/activated", False):
        LOG.info("Unattended installation is not activated in configuration")
        return
    # check if we are running in a live environment
    if not image.is_live_boot():
        LOG.error("This module can be run only in a live-boot mode")
        return

    # configure image name
    image_name: str = image.get_running_image()

    # define target drive
    install_target, target_size = find_disk()
    if not install_target:
        LOG.error("No suitable disk found for installation")
        return

    # add prefix to partitions if needed
    part_prefix: str = ""
    for dev_type in ["nvme", "mmcblk"]:
        if dev_type in install_target:
            part_prefix = "p"
    LOG.info(f"System will be installed to {install_target} ({target_size} bytes)")

    # define target rootfs size in KB (smallest unit acceptable by sgdisk)
    rootfs_size: int = (target_size - CONST_RESERVED_SPACE) // 1024
    LOG.info(f"Rootfs size: {rootfs_size} bytes")

    # create partitions
    disk.disk_cleanup(install_target)
    LOG.info("Disk cleaned")
    disk.parttable_create(install_target, rootfs_size)
    LOG.info("Partition table created")
    disk.filesystem_create(f"{install_target}{part_prefix}2", "efi")
    LOG.info("EFI filesystem created")
    disk.filesystem_create(f"{install_target}{part_prefix}3", "ext4")
    LOG.info("Ext4 filesystem created")

    # create directiroes for installation media
    prepare_tmp_disr()
    LOG.info("Prepared temporary folders for installation")

    # mount target filesystem and create required dirs inside
    disk.partition_mount(f"{install_target}{part_prefix}3", DIR_DST_ROOT)
    LOG.info(f"Partiton {install_target}{part_prefix}3 mouted to {DIR_DST_ROOT}")
    Path(f"{DIR_DST_ROOT}/boot/efi").mkdir(parents=True)
    disk.partition_mount(f"{install_target}{part_prefix}2", f"{DIR_DST_ROOT}/boot/efi")
    LOG.info(
        f"Partiton {install_target}{part_prefix}2 mouted to {DIR_DST_ROOT}/boot/efi"
    )

    # copy config
    # a config dir. It is the deepest one, so the comand will
    # create all the rest in a single step
    target_config_dir: str = f"{DIR_DST_ROOT}/boot/{image_name}/rw/opt/vyatta/etc/"
    Path(target_config_dir).mkdir(parents=True)
    # we must use Linux cp command, because Python cannot preserve ownership
    run(["cp", "-pr", "/opt/vyatta/etc/config", target_config_dir])
    LOG.info("Configuration copied from running system")

    # create a persistence.conf
    Path(f"{DIR_DST_ROOT}/persistence.conf").write_text("/ union\n")
    LOG.info("Root filesystem marked as persistent")

    # copy system image and kernel files
    for file in Path(DIR_KERNEL_SRC).iterdir():
        if file.is_file():
            copy(file, f"{DIR_DST_ROOT}/boot/{image_name}/")
            LOG.info(f"{file} installed into {DIR_DST_ROOT}/boot/{image_name}/")
    copy(FILE_ROOTFS_SRC, f"{DIR_DST_ROOT}/boot/{image_name}/{image_name}.squashfs")
    LOG.info(
        f"{FILE_ROOTFS_SRC} installed into {DIR_DST_ROOT}/boot/{image_name}/{image_name}.squashfs"
    )

    # configure GRUB
    boot_params: dict[str, str] = {
        "console_type": get_cfg_by_path(
            cfg, "vyos_install/boot_params/console_type", "kvm"
        ),
        "serial_console_num": get_cfg_by_path(
            cfg, "vyos_install/boot_params/serial_console_num", "0"
        ),
        "serial_console_speed": get_cfg_by_path(
            cfg, "vyos_install/boot_params/serial_console_speed", "9600"
        ),
        "cmdline_extra": get_cfg_by_path(
            cfg, "vyos_install/boot_params/cmdline_extra", ""
        ),
    }

    boot_vars = DEFAULT_BOOT_VARS
    if boot_params["console_type"] == "serial":
        boot_vars["console_type"] = "ttyS"
        boot_vars["console_num"] = boot_params["serial_console_num"]
        boot_vars["console_speed"] = boot_params["serial_console_speed"]

    setup_grub(DIR_DST_ROOT, boot_vars)
    LOG.info("GRUB configured")

    grub.create_structure()
    grub.version_add(
        image_name, DIR_DST_ROOT, boot_opts_config=boot_params["cmdline_extra"]
    )
    grub.set_default(image_name, DIR_DST_ROOT)

    # install GRUB
    grub.install(install_target, f"{DIR_DST_ROOT}/boot/", f"{DIR_DST_ROOT}/boot/efi")
    LOG.info("GRUB installed")

    # sort inodes (to make GRUB read config files in alphabetical order)
    grub.sort_inodes(f"{DIR_DST_ROOT}/{grub.GRUB_DIR_VYOS}")
    grub.sort_inodes(f"{DIR_DST_ROOT}/{grub.GRUB_DIR_VYOS_VERS}")

    # check if we need to disable Cloud-init
    if get_cfg_by_path(cfg, "vyos_install/ci_disable", False):
        LOG.info("Disabling Cloud-init")
        Path(f"{DIR_DST_ROOT}/boot/{image_name}/rw/etc/cloud").mkdir(parents=True)
        Path(
            f"{DIR_DST_ROOT}/boot/{image_name}/rw/etc/cloud/cloud-init.disabled"
        ).touch()

    # umount filesystems and remove temporary files
    cleanup(
        [f"{install_target}{part_prefix}2", f"{install_target}{part_prefix}3"],
        ["/mnt/installation"],
    )
    LOG.info("Temporary resources freed up")

    # check if we need to reboot
    if get_cfg_by_path(cfg, "vyos_install/post_reboot", False):
        LOG.warn("Adding reboot trigger to postconfig script")
        script_file = Path(
            "/opt/vyatta/etc/config/scripts/vyos-postconfig-bootup.script"
        )
        script_file_data: str = script_file.read_text() + "\nsystemctl reboot\n"
        script_file.write_text(script_file_data)

    # sync just in case
    sync()
