# This file is part of cloud-init. See LICENSE file for license information.

from cloudinit.config import cc_vyos
from tests.unittests.helpers import CiTestCase, mock

NETCFG = {
    "version": 2,
    "ethernets": {
        "mgmt": {
            "match": {"macaddress": "00:00:5E:00:53:02"},
            "set-name": "eth0",
            "dhcp4": True,
        },
        "dmz": {
            "match": {"macaddress": "00:00:5e:00:53:00"},
            "set-name": "eth5",
            "addresses": ["198.51.100.1/24"],
        },
        "eth10": {"addresses": ["203.0.113.1/24"]},
    },
    "bonds": {"bond0": {"interfaces": ["dmz", "eth10"]}},
    "vlans": {"vlan100": {"id": 100, "link": "mgmt"}},
}


class TestVyosNetcfgV2(CiTestCase):
    @mock.patch("cloudinit.config.cc_vyos.config_net_v2_vlan")
    @mock.patch("cloudinit.config.cc_vyos.config_net_v2_bond")
    @mock.patch("cloudinit.config.cc_vyos.config_net_v2_ethernet")
    def test_set_name_wins_over_id(self, ethernet, bond, vlan):
        config = mock.Mock()

        cc_vyos.set_config_interfaces_v2(config, NETCFG)

        self.assertEqual(
            ["eth0", "eth5", "eth10"],
            [call.args[1] for call in ethernet.call_args_list],
        )
        self.assertEqual(
            ["eth5", "eth10"], bond.call_args.args[2]["interfaces"]
        )
        self.assertEqual("eth0", vlan.call_args.args[2]["link"])
        # the datasource's own data is left as it came
        self.assertEqual(
            ["dmz", "eth10"], NETCFG["bonds"]["bond0"]["interfaces"]
        )

    @mock.patch("cloudinit.config.cc_vyos.save_store", create=True)
    @mock.patch("cloudinit.config.cc_vyos.load_store", create=True)
    @mock.patch("cloudinit.config.cc_vyos.discover_devices", create=True)
    def test_mapping_records_set_name(self, devices, load, save):
        devices.return_value = [
            {"mac": "00:00:5e:00:53:00", "key": "ID_NET_NAME_SLOT=ens4"},
            {"mac": "00:00:5e:00:53:02", "key": "ID_NET_NAME_SLOT=ens6"},
        ]
        store = {"interfaces": {}, "hardware": {}}
        load.return_value = store
        save.return_value = True

        cc_vyos.record_interface_mapping(NETCFG)

        self.assertEqual(
            {
                "eth0": "ID_NET_NAME_SLOT=ens6",
                "eth5": "ID_NET_NAME_SLOT=ens4",
            },
            store["interfaces"],
        )
        self.assertEqual(
            {"eth0": "00:00:5e:00:53:02", "eth5": "00:00:5e:00:53:00"},
            store["hardware"],
        )
        save.assert_called_once_with(store)
