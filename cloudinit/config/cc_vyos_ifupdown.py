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
from pathlib import Path
from subprocess import run, DEVNULL
from cloudinit.settings import PER_ALWAYS

LOG = logging.getLogger(__name__)

frequency = PER_ALWAYS


# cleanup network interface config file added by cloud-init
def network_cleanup() -> None:
    LOG.debug("Cleaning up network configuration applied by Cloud-Init")
    net_config_file = Path("/etc/network/interfaces.d/50-cloud-init")
    if net_config_file.exists():
        LOG.debug(f"Configuration file {net_config_file} was found")
        try:
            # get a list of interfaces that need to be deconfigured
            configured_ifaces: list[str] = (
                run(
                    ["ifquery", "-l", "-X", "lo", "-i", net_config_file],
                    capture_output=True,
                )
                .stdout.decode()
                .splitlines()
            )
            if configured_ifaces:
                for iface in configured_ifaces:
                    LOG.debug(f"Deconfiguring interface: {iface}")
                    run(["ifdown", iface], stdout=DEVNULL)
            # delete the file
            net_config_file.unlink()
            LOG.debug(f"Configuration file {net_config_file} was removed")
        except Exception as err:
            LOG.error(f"Failed to cleanup network configuration: {err}")

    udev_rules_file = Path("/etc/udev/rules.d/70-persistent-net.rules")
    if udev_rules_file.exists():
        LOG.debug(f"Configuration file {udev_rules_file} was removed")
        udev_rules_file.unlink()


def handle(*args) -> None:
    LOG.debug('Running "cc_vyos_ifupdown" module')
    network_cleanup()
