# This file is part of cloud-init. See LICENSE file for license information.

from cloudinit.config import cc_vyos
from tests.unittests.helpers import CiTestCase, mock


class FakeStore:
    """The interface map's load/save, kept in memory"""

    def __init__(self, interfaces=None, hardware=None, mounted=True):
        self.store = {
            "version": 1,
            "interfaces": dict(interfaces or {}),
            "hardware": dict(hardware or {}),
        }
        self.mounted = mounted
        self.saved = None

    def load_store(self):
        return {
            k: (dict(v) if isinstance(v, dict) else v)
            for k, v in self.store.items()
        }

    def save_store(self, store):
        if not self.mounted:
            return False
        self.saved = store
        return True


class FakeConfig:
    def __init__(self):
        self.set_calls = []

    def set(self, path, value=None, replace=True):
        self.set_calls.append((path, value))

    def set_tag(self, path):
        pass

    def exists(self, path):
        return False

    def return_values(self, path):
        return []

    def addresses(self):
        """interface name -> the addresses set on it"""
        found = {}
        for path, value in self.set_calls:
            if path[:2] == ["interfaces", "ethernet"] and path[3:] == [
                "address"
            ]:
                found.setdefault(path[2], []).append(value)
        return found


# Azure, four NICs: the names cloud-init gives them, in the order Azure
# lists them, and the MAC of each - measured on a fresh deployment
AZURE = {
    "eth0": "00:0d:3a:47:38:1d",
    "eth1": "00:0d:3a:47:3b:29",
    "eth2": "00:0d:3a:47:33:ad",
    "eth3": "00:0d:3a:47:3b:f8",
}


def key(mac):
    return "ID_NET_NAME_MAC=enx" + mac.lower().replace(":", "")


def store(names):
    """an interface map recording each name on its MAC"""
    return {
        "version": 1,
        "interfaces": {n: key(m) for n, m in names.items()},
        "hardware": dict(names),
    }


def v1(nics):
    """network-config v1: one physical NIC per name, each with its own
    static address so the rendered configuration shows where it went"""
    return {
        "version": 1,
        "config": [
            {
                "type": "physical",
                "name": name,
                "mac_address": mac.upper(),
                "subnets": [
                    {"type": "static", "address": "10.0.{}.4/24".format(i)}
                ],
            }
            for i, (name, mac) in enumerate(nics.items())
        ],
    }


class TestMacBindings(CiTestCase):
    def setUp(self):
        super().setUp()
        cc_vyos.planned_map = None

    def test_azure_on_a_map_image_records_no_hw_id(self):
        config = FakeConfig()
        with mock.patch.object(cc_vyos, "use_interface_map", True):
            cc_vyos.set_ether_mac(config, "eth0", AZURE["eth0"])
        self.assertEqual([], config.set_calls)

    def test_other_platforms_keep_hw_id(self):
        # the map is written on Azure only; elsewhere is an open question
        config = FakeConfig()
        with mock.patch.object(cc_vyos, "use_interface_map", False):
            cc_vyos.set_ether_mac(config, "eth0", AZURE["eth0"])
        self.assertEqual(
            [(["interfaces", "ethernet", "eth0", "hw-id"], AZURE["eth0"])],
            config.set_calls,
        )

    def test_the_mac_is_not_logged(self):
        with mock.patch.object(cc_vyos.logger, "debug") as debug:
            cc_vyos.set_ether_mac(FakeConfig(), "eth0", AZURE["eth0"])
        self.assertNotIn(AZURE["eth0"], debug.call_args[0][0])

    def test_network_config_v1_and_v2_give_the_same_macs(self):
        netcfg2 = {
            "version": 2,
            "ethernets": {
                n: {"match": {"macaddress": m.upper()}}
                for n, m in AZURE.items()
            },
        }
        self.assertEqual(AZURE, cc_vyos.netcfg_macs(v1(AZURE)))
        self.assertEqual(AZURE, cc_vyos.netcfg_macs(netcfg2))

    def test_a_fresh_instance_takes_the_platform_names(self):
        st = store({})
        names = cc_vyos.plan_interface_names(AZURE, st, set(AZURE.values()))
        self.assertEqual({n: n for n in AZURE}, names)
        self.assertEqual(store(AZURE)["interfaces"], st["interfaces"])
        self.assertEqual(AZURE, st["hardware"])

    def test_a_rerun_after_an_adoption_moves_nothing(self):
        # measured on 5479.0.8: after LAN2's NIC was re-created and adopted
        # as eth2, Azure lists it last. If cloud-init runs again on the same
        # NICs, the names hold and each NIC's settings follow its own name
        names = {
            "eth0": "70:a8:a5:39:2e:cd",
            "eth1": "70:a8:a5:39:2d:a6",
            "eth2": "60:45:bd:96:1c:b6",
            "eth3": "70:a8:a5:39:2c:53",
        }
        imds = {
            "eth0": "70:a8:a5:39:2e:cd",
            "eth1": "70:a8:a5:39:2d:a6",
            "eth2": "70:a8:a5:39:2c:53",
            "eth3": "60:45:bd:96:1c:b6",
        }
        st = store(names)
        planned = cc_vyos.plan_interface_names(imds, st, set(names.values()))
        self.assertEqual(
            {"eth0": "eth0", "eth1": "eth1", "eth2": "eth3", "eth3": "eth2"},
            planned,
        )
        self.assertEqual(store(names), st)

    def test_a_vacant_name_whose_nic_has_another_name_is_kept_from_new_nics(
        self,
    ):
        # a VM rebuilt from its disk: the old WAN NIC is gone, LAN1's NIC is
        # now listed first, plus a new NIC. LAN1's NIC keeps eth1 and gets
        # what Azure lists for it; eth0 must not go to the new NIC (FR-1), so
        # it is recorded as missing and the new NIC is named eth2
        old_wan, lan1, new = (
            "00:0d:3a:aa:00:0a",
            "00:0d:3a:aa:00:0b",
            "60:45:bd:00:00:01",
        )
        st = store({"eth0": old_wan, "eth1": lan1})
        with mock.patch.object(cc_vyos.logger, "warning") as warning:
            planned = cc_vyos.plan_interface_names(
                {"eth0": lan1, "eth1": new}, st, {lan1, new}
            )
        self.assertEqual({"eth0": "eth1", "eth1": "eth2"}, planned)
        self.assertEqual(key(old_wan), st["interfaces"]["eth0"])
        self.assertEqual(key(new), st["interfaces"]["eth2"])
        self.assertEqual(["eth0"], st["absent"])
        self.assertIn(
            "eth0", " ".join(c[0][0] for c in warning.call_args_list)
        )

    def test_a_lone_nic_keyed_on_its_path_is_known_by_its_address(self):
        # two NICs, the primary removed: the survivor ran alone as eth1, so
        # its key is the shared VMBus path. cloud-init runs again with Azure
        # listing it as eth0 - it must not also become eth0 and run the
        # removed primary's configuration (FR3-1)
        primary, lone = "00:0d:3a:aa:00:0a", "00:0d:3a:aa:00:0b"
        st = store({"eth0": primary, "eth1": lone})
        st["interfaces"]["eth1"] = "ID_PATH=acpi-MSFT1000:00"
        planned = cc_vyos.plan_interface_names({"eth0": lone}, st, {lone})
        self.assertEqual({"eth0": "eth1"}, planned)
        self.assertEqual(key(primary), st["interfaces"]["eth0"])
        self.assertEqual("ID_PATH=acpi-MSFT1000:00", st["interfaces"]["eth1"])
        self.assertEqual(["eth0"], st["absent"])

    def test_a_contested_name_is_added_to_the_names_already_missing(self):
        old_wan, lan1, gone = (
            "00:0d:3a:aa:00:0a",
            "00:0d:3a:aa:00:0b",
            "00:0d:3a:aa:00:0c",
        )
        st = store({"eth0": old_wan, "eth1": lan1, "eth3": gone})
        st["absent"] = ["eth3"]
        cc_vyos.plan_interface_names({"eth0": lan1}, st, {lan1})
        self.assertEqual(["eth0", "eth3"], st["absent"])

    def test_a_name_with_no_recorded_address_is_kept(self):
        # nothing on record to say its NIC is gone, so the NIC the platform
        # lists under it gets the lowest free name instead
        st = store({})
        st["interfaces"]["eth1"] = key("00:0d:3a:aa:00:0b")
        planned = cc_vyos.plan_interface_names(
            {"eth1": "00:0d:3a:aa:00:0c"}, st, {"00:0d:3a:aa:00:0c"}
        )
        self.assertEqual({"eth1": "eth0"}, planned)
        self.assertEqual(key("00:0d:3a:aa:00:0b"), st["interfaces"]["eth1"])
        self.assertEqual(key("00:0d:3a:aa:00:0c"), st["interfaces"]["eth0"])

    def test_a_nic_still_here_keeps_its_name_when_the_platform_omits_it(self):
        # Azure leaves a NIC without an IP address out of network-config, so
        # the NIC it lists under that NIC's name is another one
        a, b, x = "00:0d:3a:aa:00:0a", "00:0d:3a:aa:00:0b", "00:0d:3a:aa:00:0f"
        st = store({"eth0": a, "eth1": b})
        planned = cc_vyos.plan_interface_names(
            {"eth0": a, "eth1": x}, st, {a, b, x}
        )
        self.assertEqual({"eth0": "eth0", "eth1": "eth2"}, planned)
        self.assertEqual(key(b), st["interfaces"]["eth1"])

    def test_names_are_ordered_by_number(self):
        self.assertEqual(
            ["eth1", "eth2", "eth10"],
            sorted(["eth10", "eth2", "eth1"], key=cc_vyos.name_order),
        )

    def test_a_name_not_in_the_map_is_neither_warned_about_nor_reserved(self):
        lan1 = "00:0d:3a:aa:00:0b"
        st = store({"eth1": lan1})
        with mock.patch.object(cc_vyos.logger, "warning") as warning:
            planned = cc_vyos.plan_interface_names({"eth0": lan1}, st, {lan1})
        self.assertEqual({"eth0": "eth1"}, planned)
        self.assertNotIn("eth0", st["interfaces"])
        self.assertNotIn("absent", st)
        warning.assert_not_called()

    def test_a_disk_on_new_nics_takes_the_platform_names(self):
        # restore as a new VM: every recorded NIC is gone, and this runs once
        # for the new instance with the order Azure lists the new NICs in
        old = {n: "00:0d:3a:48:00:0" + n[-1] for n in AZURE}
        st = store(old)
        planned = cc_vyos.plan_interface_names(AZURE, st, set(AZURE.values()))
        self.assertEqual({n: n for n in AZURE}, planned)
        self.assertEqual(store(AZURE)["interfaces"], st["interfaces"])

    def test_a_mac_is_never_given_two_names(self):
        st = store({"eth5": AZURE["eth0"]})
        planned = cc_vyos.plan_interface_names(
            {"eth0": AZURE["eth0"]}, st, {AZURE["eth0"]}
        )
        self.assertEqual({"eth0": "eth5"}, planned)
        self.assertNotIn("eth0", st["interfaces"])

    def test_a_slot_keyed_map_is_followed_by_recorded_address(self):
        # a map whose names are keyed on PCI paths, as the naming pass keeps
        # them on a platform with slots: a NIC is found by its recorded MAC
        macs = {"eth0": "52:54:00:00:00:00", "eth1": "52:54:00:00:00:30"}
        st = store(macs)
        st["interfaces"] = {"eth0": "ID_PATH=pci-1", "eth1": "ID_PATH=pci-2"}
        planned = cc_vyos.plan_interface_names(
            {"eth0": macs["eth1"], "eth1": macs["eth0"]},
            st,
            set(macs.values()),
        )
        self.assertEqual({"eth0": "eth1", "eth1": "eth0"}, planned)
        self.assertEqual(
            {"eth0": "ID_PATH=pci-1", "eth1": "ID_PATH=pci-2"},
            st["interfaces"],
        )

    def test_a_nic_not_yet_in_sysfs_keeps_its_one_name(self):
        # its MAC is on record under eth1; it must not get a second name
        lan1 = "00:0d:3a:aa:00:0b"
        st = store({"eth1": lan1})
        planned = cc_vyos.plan_interface_names({"eth0": lan1}, st, set())
        self.assertEqual({"eth0": "eth1"}, planned)
        self.assertEqual({"eth1": key(lan1)}, st["interfaces"])

    def test_a_free_name_is_never_one_a_nic_without_a_mac_uses(self):
        a, b = "00:0d:3a:aa:00:0a", "00:0d:3a:aa:00:0b"
        st = store({"eth1": a})
        st["interfaces"]["eth0"] = key("00:0d:3a:aa:00:0f")
        planned = cc_vyos.plan_interface_names(
            {"eth0": a, "eth1": b}, st, {a, b}, unbound={"eth2"}
        )
        self.assertEqual({"eth0": "eth1", "eth1": "eth3"}, planned)

    def test_the_names_network_config_uses_are_listed(self):
        netcfg = v1(AZURE)
        netcfg["config"].append({"type": "physical", "name": "eth7"})
        self.assertEqual(
            set(AZURE) | {"eth7"}, cc_vyos.netcfg_ethernets(netcfg)
        )

    def test_v1_references_are_renamed(self):
        netcfg = {
            "version": 1,
            "config": [
                {"type": "physical", "name": "eth0"},
                {"type": "physical", "name": "eth1"},
                {
                    "type": "bond",
                    "name": "bond0",
                    "bond_interfaces": ["eth0", "eth1"],
                    "params": {"primary": "eth0"},
                },
                {
                    "type": "bridge",
                    "name": "br0",
                    "bridge_interfaces": ["eth1"],
                    "params": {
                        "bridge_pathcost": ["eth1 50"],
                        "bridge_portprio": ["eth1 28"],
                    },
                },
                {"type": "vlan", "name": "eth0.5", "vlan_link": "eth0"},
            ],
        }
        renamed = cc_vyos.rename_interfaces(
            netcfg, {"eth0": "eth1", "eth1": "eth0"}
        )["config"]
        self.assertEqual(["eth1", "eth0"], [i["name"] for i in renamed[:2]])
        self.assertEqual(["eth1", "eth0"], renamed[2]["bond_interfaces"])
        self.assertEqual("eth1", renamed[2]["params"]["primary"])
        self.assertEqual(["eth0"], renamed[3]["bridge_interfaces"])
        self.assertEqual(["eth0 50"], renamed[3]["params"]["bridge_pathcost"])
        self.assertEqual(["eth0 28"], renamed[3]["params"]["bridge_portprio"])
        self.assertEqual("eth1", renamed[4]["vlan_link"])

    def test_v2_bridge_members_are_renamed(self):
        netcfg = {
            "version": 2,
            "ethernets": {"eth0": {}},
            "bridges": {"br0": {"interfaces": ["eth0"]}},
        }
        renamed = cc_vyos.rename_interfaces(netcfg, {"eth0": "eth3"})
        self.assertEqual(["eth3"], renamed["bridges"]["br0"]["interfaces"])

    def test_malformed_port_entries_are_left_for_the_renderer(self):
        netcfg = {
            "version": 1,
            "config": [
                {
                    "type": "bridge",
                    "name": "br0",
                    "params": {"bridge_pathcost": ["", 5, "eth0 50"]},
                }
            ],
        }
        renamed = cc_vyos.rename_interfaces(netcfg, {"eth0": "eth1"})
        self.assertEqual(
            ["", 5, "eth1 50"],
            renamed["config"][0]["params"]["bridge_pathcost"],
        )

    def test_v2_names_are_listed(self):
        netcfg = {"version": 2, "ethernets": {"eth0": {}, "eth4": {}}}
        self.assertEqual({"eth0", "eth4"}, cc_vyos.netcfg_ethernets(netcfg))

    def _map(self, fake, netcfg, present):
        with mock.patch.object(
            cc_vyos, "ifname_store", fake
        ), mock.patch.object(cc_vyos, "present_macs", return_value=present):
            return cc_vyos.map_interface_names(netcfg)

    def test_a_free_name_skips_a_nic_network_config_lists_without_a_mac(self):
        # A keeps eth1; B's platform name is held, and eth0 is used by a NIC
        # network-config gives no MAC, so B is named eth2
        a, b = "00:0d:3a:aa:00:0a", "00:0d:3a:aa:00:0b"
        netcfg = v1({"eth1": a, "eth2": b})
        netcfg["config"][1]["name"] = "eth1"
        netcfg["config"][0]["name"] = "eth2"
        netcfg["config"].append({"type": "physical", "name": "eth0"})
        fake = FakeStore({"eth1": key(a), "eth2": key("00:0d:3a:aa:00:0f")})
        fake.store["hardware"] = {"eth1": a, "eth2": "00:0d:3a:aa:00:0f"}
        renamed = self._map(fake, netcfg, {a, b, "00:0d:3a:aa:00:0f"})
        names = sorted(i["name"] for i in renamed["config"])
        self.assertEqual(["eth0", "eth1", "eth3"], names)

    def test_a_nic_without_a_mac_never_shares_a_named_nic_s_settings(self):
        # the map names A eth1; network-config lists A as eth0 and gives a
        # NIC without a MAC the name eth1: that entry is not rendered
        a = "00:0d:3a:aa:00:0a"
        netcfg = v1({"eth0": a})
        netcfg["config"].append(
            {
                "type": "physical",
                "name": "eth1",
                "subnets": [{"type": "static", "address": "10.9.9.9/24"}],
            }
        )
        fake = FakeStore({"eth1": key(a)}, {"eth1": a})
        with mock.patch.object(cc_vyos.logger, "warning") as warning:
            renamed = self._map(fake, netcfg, {a})
        self.assertEqual(["eth1"], [i["name"] for i in renamed["config"]])
        self.assertEqual(
            "10.0.0.4/24", renamed["config"][0]["subnets"][0]["address"]
        )
        self.assertIn("eth1", warning.call_args[0][0])

    def test_params_that_are_not_a_mapping_are_left_for_the_renderer(self):
        for params in (["x"], "x", None):
            netcfg = {
                "version": 1,
                "config": [
                    {"type": "bond", "name": "bond0", "params": params}
                ],
            }
            renamed = cc_vyos.rename_interfaces(netcfg, {"eth0": "eth1"})
            self.assertEqual(params, renamed["config"][0]["params"])

    def test_what_refers_to_a_dropped_interface_is_dropped_too(self):
        v1cfg = {
            "version": 1,
            "config": [
                {"type": "physical", "name": "eth1"},
                {"type": "physical", "name": "eth2"},
                {
                    "type": "bond",
                    "name": "bond0",
                    "bond_interfaces": ["eth1", "eth2"],
                    "params": {"primary": "eth1"},
                },
                {
                    "type": "bridge",
                    "name": "br0",
                    "bridge_interfaces": ["eth1"],
                    "params": {"bridge_pathcost": ["eth1 50", "eth2 60"]},
                },
                {"type": "vlan", "name": "eth1.7", "vlan_link": "eth1"},
            ],
        }
        out = cc_vyos.drop_interfaces(v1cfg, {"eth1"})["config"]
        self.assertEqual(["eth2", "bond0", "br0"], [i["name"] for i in out])
        self.assertEqual(["eth2"], out[1]["bond_interfaces"])
        self.assertNotIn("primary", out[1]["params"])
        self.assertEqual([], out[2]["bridge_interfaces"])
        self.assertEqual(["eth2 60"], out[2]["params"]["bridge_pathcost"])
        v2cfg = {
            "version": 2,
            "ethernets": {"eth1": {}, "eth2": {}},
            "bonds": {"bond0": {"interfaces": ["eth1", "eth2"]}},
            "bridges": {"br0": {"interfaces": ["eth1"]}},
            "vlans": {"eth1.7": {"link": "eth1"}, "eth2.8": {"link": "eth2"}},
        }
        out = cc_vyos.drop_interfaces(v2cfg, {"eth1"})
        self.assertEqual(["eth2"], list(out["ethernets"]))
        self.assertEqual(["eth2"], out["bonds"]["bond0"]["interfaces"])
        self.assertEqual([], out["bridges"]["br0"]["interfaces"])
        self.assertEqual(["eth2.8"], list(out["vlans"]))
        self.assertEqual(
            ["eth1", "eth2"], v2cfg["bonds"]["bond0"]["interfaces"]
        )

    def test_each_run_starts_without_a_planned_map(self):
        cc_vyos.planned_map = store(AZURE)
        with mock.patch.object(
            cc_vyos, "interface_map_wanted", return_value=False
        ):
            cc_vyos.select_interface_map("NoCloud")
        self.assertIsNone(cc_vyos.planned_map)

    def _render(self, fake, netcfg, present):
        config = FakeConfig()
        with mock.patch.object(
            cc_vyos, "ifname_store", fake
        ), mock.patch.object(
            cc_vyos, "present_macs", return_value=present
        ), mock.patch.object(
            cc_vyos, "set_ether_mtu"
        ), mock.patch.object(
            cc_vyos, "use_interface_map", True
        ):
            netcfg = cc_vyos.map_interface_names(netcfg)
            for item in netcfg["config"]:
                cc_vyos.set_config_interfaces_v1(config, item)
        return config.addresses()

    def test_a_rerun_renders_each_nic_under_the_name_it_keeps(self):
        # the map names A eth0 and B eth1; Azure now lists B first. Each
        # NIC's settings must land on the name that NIC keeps
        a, b = "00:0d:3a:aa:00:0a", "00:0d:3a:aa:00:0b"
        fake = FakeStore(store({"eth0": a, "eth1": b})["interfaces"])
        fake.store["hardware"] = {"eth0": a, "eth1": b}
        rendered = self._render(fake, v1({"eth0": b, "eth1": a}), {a, b})
        # v1() gives the first NIC (B) 10.0.0.4 and the second (A) 10.0.1.4
        self.assertEqual(
            {"eth0": ["10.0.1.4/24"], "eth1": ["10.0.0.4/24"]}, rendered
        )
        # and the map is left as it was
        self.assertEqual(store({"eth0": a, "eth1": b}), cc_vyos.planned_map)

    def test_a_name_the_map_lacks_does_not_send_settings_to_another_nic(
        self,
    ):
        # only eth1 = A on record; Azure lists eth0 = A, eth1 = B. A keeps
        # eth1 with its own settings, B is named eth0 with its own
        a, b = "00:0d:3a:aa:00:0a", "00:0d:3a:aa:00:0b"
        fake = FakeStore({"eth1": key(a)}, {"eth1": a})
        rendered = self._render(fake, v1({"eth0": a, "eth1": b}), {a, b})
        self.assertEqual(
            {"eth1": ["10.0.0.4/24"], "eth0": ["10.0.1.4/24"]}, rendered
        )
        self.assertEqual(key(b), cc_vyos.planned_map["interfaces"]["eth0"])
        self.assertEqual(key(a), cc_vyos.planned_map["interfaces"]["eth1"])

    def test_names_are_renamed_everywhere_they_are_used(self):
        netcfg = {
            "version": 2,
            "ethernets": {"eth0": {"a": 1}, "eth1": {"b": 2}},
            "bonds": {"bond0": {"interfaces": ["eth0", "eth1"]}},
            "vlans": {"eth0.5": {"link": "eth0"}},
        }
        renamed = cc_vyos.rename_interfaces(
            netcfg, {"eth0": "eth1", "eth1": "eth0"}
        )
        self.assertEqual(
            {"eth1": {"a": 1}, "eth0": {"b": 2}}, renamed["ethernets"]
        )
        self.assertEqual(
            ["eth1", "eth0"], renamed["bonds"]["bond0"]["interfaces"]
        )
        self.assertEqual("eth1", renamed["vlans"]["eth0.5"]["link"])
        self.assertEqual({"a": 1}, netcfg["ethernets"]["eth0"])

    def test_a_broken_import_on_a_map_image_is_reported_not_hidden(self):
        # the image has the map, so hw-id would be rejected: the bindings are
        # not written as hw-id either, and the failure is logged
        netcfg = v1({"eth0": AZURE["eth0"]})
        with mock.patch.object(
            cc_vyos, "ifname_store", None
        ), mock.patch.object(cc_vyos.logger, "error") as error:
            self.assertEqual(netcfg, cc_vyos.map_interface_names(netcfg))
        error.assert_called_once()
        self.assertIn("eth0", error.call_args[0][0])
        self.assertIsNone(cc_vyos.planned_map)

    def test_the_map_image_is_recognised_by_its_resolver(self):
        with mock.patch.object(
            cc_vyos, "INTERFACE_MAP_RESOLVER", self.tmp_path("absent")
        ):
            self.assertFalse(cc_vyos.interface_map_image())
        present = self.tmp_path("resolver")
        open(present, "w").close()
        with mock.patch.object(cc_vyos, "INTERFACE_MAP_RESOLVER", present):
            self.assertTrue(cc_vyos.interface_map_image())

    def test_the_map_is_wanted_on_azure_only(self):
        with mock.patch.object(
            cc_vyos, "interface_map_image", return_value=True
        ):
            self.assertTrue(cc_vyos.interface_map_wanted("Azure"))
            for other in ("NoCloud", "OpenStack", "ConfigDrive", "OVF"):
                self.assertFalse(cc_vyos.interface_map_wanted(other))
        with mock.patch.object(
            cc_vyos, "interface_map_image", return_value=False
        ):
            self.assertFalse(cc_vyos.interface_map_wanted("Azure"))

    def test_the_module_does_not_import_the_map_at_load(self):
        # other platforms must not depend on the vyos package: with the
        # module importable, loading cc_vyos still must not import it
        import importlib
        import sys
        import types

        package = types.ModuleType("vyos.ifconfig")
        package.ifname_store = FakeStore()
        with mock.patch.dict(sys.modules, {"vyos.ifconfig": package}):
            mod = importlib.reload(cc_vyos)
            self.assertIsNone(mod.ifname_store)
        importlib.reload(cc_vyos)

    def _select(self, dsname, image=True):
        import sys
        import types

        package = types.ModuleType("vyos.ifconfig")
        package.ifname_store = FakeStore()
        with mock.patch.dict(
            sys.modules, {"vyos.ifconfig": package}
        ), mock.patch.object(cc_vyos, "ifname_store", None), mock.patch.object(
            cc_vyos, "use_interface_map", False
        ), mock.patch.object(
            cc_vyos, "interface_map_image", return_value=image
        ):
            cc_vyos.select_interface_map(dsname)
            return (
                cc_vyos.use_interface_map,
                cc_vyos.ifname_store is package.ifname_store,
            )

    def test_azure_on_a_map_image_selects_and_imports_the_map(self):
        self.assertEqual((True, True), self._select("Azure"))

    def test_other_datasources_neither_select_nor_import_it(self):
        self.assertEqual((False, False), self._select("NoCloud"))
        self.assertEqual((False, False), self._select("Azure", image=False))

    def _write(self, path, fake, planned):
        config = mock.Mock()
        config.to_string.return_value = "interfaces {}\n"
        with mock.patch.object(
            cc_vyos, "ifname_store", fake
        ), mock.patch.object(cc_vyos, "planned_map", planned):
            return cc_vyos.write_config(config, path)

    def test_the_map_is_saved_after_the_configuration(self):
        fake, planned = FakeStore(), store(AZURE)
        path = self.tmp_path("config.boot")
        self.assertTrue(self._write(path, fake, planned))
        self.assertEqual(planned, fake.saved)
        with open(path) as f:
            self.assertEqual("interfaces {}\n", f.read())

    def test_no_map_without_the_configuration(self):
        fake = FakeStore()
        path = self.tmp_path("missing-dir/config.boot")
        self.assertFalse(self._write(path, fake, store(AZURE)))
        self.assertIsNone(fake.saved)

    def test_other_platforms_write_only_the_configuration(self):
        path = self.tmp_path("config.boot")
        self.assertTrue(self._write(path, None, None))
        with open(path) as f:
            self.assertEqual("interfaces {}\n", f.read())

    def test_unmounted_volume_writes_no_map(self):
        fake = FakeStore(mounted=False)
        with mock.patch.object(cc_vyos.logger, "warning") as warning:
            self.assertTrue(
                self._write(self.tmp_path("config.boot"), fake, store(AZURE))
            )
        self.assertIsNone(fake.saved)
        warning.assert_called_once()


def v2(nics):
    """network-config v2 as Azure gives it: set-name by the order Azure
    lists the NICs in"""
    return {
        "version": 2,
        "ethernets": {
            name: {
                "dhcp4": True,
                "match": {"macaddress": mac, "driver": "hv_netvsc"},
                "set-name": name,
            }
            for name, mac in nics.items()
        },
    }


def set_names(netcfg):
    return {
        name: item.get("set-name")
        for name, item in netcfg["ethernets"].items()
    }


class TestBootRenames(CiTestCase):
    """cloud-init's own renaming at every boot, before cc_vyos runs"""

    def _boot(self, fake, netcfg, dsname="Azure", present=frozenset()):
        import sys
        import types

        package = types.ModuleType("vyos.ifconfig")
        package.ifname_store = fake
        with mock.patch.dict(
            sys.modules, {"vyos.ifconfig": package}
        ), mock.patch.object(
            cc_vyos, "interface_map_image", return_value=True
        ), mock.patch.object(
            cc_vyos, "present_macs", return_value=set(present)
        ):
            return cc_vyos.boot_interface_names(netcfg, dsname)

    def test_a_nic_keeps_its_name_when_one_before_it_is_removed(self):
        # measured on Azure: LAN1 (C, eth2) removed, so Azure lists LAN2
        # (D, eth3) third and network-config says set-name eth2 for it
        a, b, c, d = (
            "00:0d:3a:27:84:8f",
            "00:0d:3a:27:8d:35",
            "00:0d:3a:27:8d:da",
            "00:0d:3a:27:8b:58",
        )
        fake = FakeStore(
            store({"eth0": a, "eth1": b, "eth2": c, "eth3": d})["interfaces"],
            {"eth0": a, "eth1": b, "eth2": c, "eth3": d},
        )
        netcfg = v2({"eth0": a, "eth1": b, "eth2": d})
        renamed = self._boot(fake, netcfg)
        self.assertEqual(
            {"eth0": "eth0", "eth1": "eth1", "eth2": "eth3"},
            set_names(renamed),
        )
        # what cloud-init renames by
        from cloudinit.net import extract_physdevs

        self.assertIn(
            [d, "eth3", "hv_netvsc", None], extract_physdevs(renamed)
        )
        # the configuration it renders from is not changed
        self.assertEqual("eth2", netcfg["ethernets"]["eth2"]["set-name"])

    def test_a_first_boot_renames_as_the_platform_lists(self):
        netcfg = v2(AZURE)
        self.assertEqual(netcfg, self._boot(FakeStore(), netcfg))

    def test_a_nic_whose_platform_name_is_held_gets_a_free_name(self):
        # the map names A eth1; Azure lists A as eth0 and a NIC the map does
        # not know (B) as eth1, which A holds
        a, b = "00:0d:3a:aa:00:0a", "00:0d:3a:aa:00:0b"
        fake = FakeStore({"eth1": key(a)}, {"eth1": a})
        renamed = self._boot(fake, v2({"eth0": a, "eth1": b}))
        self.assertEqual({"eth0": "eth1", "eth1": "eth0"}, set_names(renamed))

    def test_a_new_nic_listed_under_a_held_name_skips_a_removed_nic_s(self):
        # measured on Azure (X12): D (eth3) removed and a boot taken; the new
        # NIC X is listed third, under eth2, which C holds - it must not keep
        # the name the kernel gave it (eth3, D's)
        a, b, c, d, x = (
            "00:0d:3a:aa:00:0a",
            "00:0d:3a:aa:00:0b",
            "00:0d:3a:aa:00:0c",
            "00:0d:3a:aa:00:0d",
            "00:0d:3a:aa:00:0f",
        )
        names = {"eth0": a, "eth1": b, "eth2": c, "eth3": d}
        fake = FakeStore(store(names)["interfaces"], names)
        fake.store["absent"] = ["eth3"]
        renamed = self._boot(
            fake, v2({"eth0": a, "eth1": b, "eth2": x, "eth3": c})
        )
        self.assertEqual(
            {"eth0": "eth0", "eth1": "eth1", "eth2": "eth4", "eth3": "eth2"},
            set_names(renamed),
        )

    def test_a_new_nic_takes_a_free_platform_name(self):
        # a replaced NIC: C (eth2) is gone and Azure lists the new X as eth2
        a, c, x = "00:0d:3a:aa:00:0a", "00:0d:3a:aa:00:0c", "00:0d:3a:aa:00:0f"
        fake = FakeStore(
            store({"eth0": a, "eth2": c})["interfaces"], {"eth0": a, "eth2": c}
        )
        renamed = self._boot(fake, v2({"eth0": a, "eth2": x}))
        self.assertEqual({"eth0": "eth0", "eth2": "eth2"}, set_names(renamed))

    def test_a_new_nic_does_not_take_a_removed_nic_s_name(self):
        # D (eth3) was removed and a boot taken, so eth3 is absent; a new NIC
        # X is then listed in D's place
        a, b, c, d, x, y = (
            "00:0d:3a:aa:00:0a",
            "00:0d:3a:aa:00:0b",
            "00:0d:3a:aa:00:0c",
            "00:0d:3a:aa:00:0d",
            "00:0d:3a:aa:00:0f",
            "00:0d:3a:aa:00:10",
        )
        names = {"eth0": a, "eth1": b, "eth2": c, "eth3": d}
        fake = FakeStore(store(names)["interfaces"], names)
        fake.store["absent"] = ["eth3"]
        renamed = self._boot(
            fake, v2({"eth0": a, "eth1": b, "eth2": c, "eth3": x})
        )
        self.assertEqual(
            {"eth0": "eth0", "eth1": "eth1", "eth2": "eth2", "eth3": "eth4"},
            set_names(renamed),
        )
        # two of them each get their own name
        fake.store["absent"] = ["eth2", "eth3"]
        renamed = self._boot(
            fake, v2({"eth0": a, "eth1": b, "eth2": x, "eth3": y})
        )
        self.assertEqual(
            {"eth0": "eth0", "eth1": "eth1", "eth2": "eth4", "eth3": "eth5"},
            set_names(renamed),
        )

    def test_a_new_nic_does_not_take_the_name_of_an_unlisted_nic_here(self):
        # Y (eth2) is still attached, but network-config does not list it
        # (cloud-init's one-NIC fallback, for one); a new NIC X listed as
        # eth2 gets a free name, as the naming pass gives it, not Y's
        a, b, y, x = (
            "00:0d:3a:aa:00:0a",
            "00:0d:3a:aa:00:0b",
            "00:0d:3a:aa:00:0c",
            "00:0d:3a:aa:00:0f",
        )
        names = {"eth0": a, "eth1": b, "eth2": y}
        fake = FakeStore(store(names)["interfaces"], names)
        renamed = self._boot(
            fake,
            v2({"eth0": a, "eth1": b, "eth2": x}),
            present={a, b, y, x},
        )
        self.assertEqual(
            {"eth0": "eth0", "eth1": "eth1", "eth2": "eth3"},
            set_names(renamed),
        )
        # once Y is gone, X may take eth2, as before
        renamed = self._boot(
            fake, v2({"eth0": a, "eth1": b, "eth2": x}), present={a, b, x}
        )
        self.assertEqual(
            {"eth0": "eth0", "eth1": "eth1", "eth2": "eth2"},
            set_names(renamed),
        )

    def test_an_unlisted_nic_recorded_in_upper_case_keeps_its_name(self):
        a, y, x = "00:0d:3a:aa:00:0a", "00:0d:3a:aa:00:0c", "00:0d:3a:aa:00:0f"
        names = {"eth0": a, "eth2": y}
        fake = FakeStore(
            store(names)["interfaces"], {"eth0": a, "eth2": y.upper()}
        )
        renamed = self._boot(
            fake, v2({"eth0": a, "eth2": x}), present={a, y, x}
        )
        self.assertEqual({"eth0": "eth0", "eth2": "eth1"}, set_names(renamed))

    def test_a_lone_nic_without_an_address_on_record_keeps_its_name(self):
        # keyed on its VMBus path, no address recorded; an interface with
        # no address (a tunnel) reads as '' in sysfs
        a = "00:0d:3a:aa:00:0a"
        fake = FakeStore({"eth0": "ID_PATH=acpi-MSFT1000:00"}, {})
        renamed = self._boot(fake, v2({"eth0": a}), present={a, ""})
        self.assertEqual({"eth0": "eth0"}, set_names(renamed))

    def test_a_free_name_at_boot_skips_a_nic_listed_without_a_mac(self):
        # eth0 reserved, eth1 = A; network-config lists eth0 = A, eth1 = B
        # and an eth2 without a MAC: B gets eth3, as when the names are
        # planned for a new instance, not the eth2 the other entry uses
        a, b, r = "00:0d:3a:aa:00:0a", "00:0d:3a:aa:00:0b", "00:0d:3a:aa:00:0e"
        fake = FakeStore(
            {"eth0": key(r), "eth1": key(a)}, {"eth0": r, "eth1": a}
        )
        fake.store["absent"] = ["eth0"]
        netcfg = v2({"eth0": a, "eth1": b})
        netcfg["ethernets"]["eth2"] = {"dhcp4": True}
        renamed = self._boot(fake, netcfg)
        self.assertEqual(
            {"eth0": "eth1", "eth1": "eth3", "eth2": None},
            set_names(renamed),
        )

    def test_v1_references_are_renamed_at_boot(self):
        # what is rendered at boot follows the NICs it is renamed to
        a, b = "00:0d:3a:aa:00:0a", "00:0d:3a:aa:00:0b"
        fake = FakeStore(
            store({"eth0": b, "eth1": a})["interfaces"], {"eth0": b, "eth1": a}
        )
        netcfg = {
            "version": 1,
            "config": [
                {"type": "physical", "name": "eth0", "mac_address": a},
                {"type": "physical", "name": "eth1", "mac_address": b},
                {
                    "type": "bond",
                    "name": "bond0",
                    "bond_interfaces": ["eth0"],
                    "params": {"bond-primary": "eth0"},
                },
                {"type": "vlan", "name": "eth0.5", "vlan_link": "eth0"},
                {
                    "type": "nameserver",
                    "address": ["10.0.0.53"],
                    "interface": "eth0",
                },
            ],
        }
        renamed = self._boot(fake, netcfg)
        config = renamed["config"]
        self.assertEqual(["eth1", "eth0"], [c["name"] for c in config[:2]])
        self.assertEqual(["eth1"], config[2]["bond_interfaces"])
        self.assertEqual("eth1", config[2]["params"]["bond-primary"])
        self.assertEqual("eth1", config[3]["vlan_link"])
        self.assertEqual("eth1", config[4]["interface"])
        # and cloud-init can parse what it renders from
        from cloudinit.net.network_state import parse_net_config_data

        parse_net_config_data(renamed)
        self.assertEqual("eth0", netcfg["config"][0]["name"])

    def test_network_config_v1_is_renamed_too(self):
        a, b = "00:0d:3a:aa:00:0a", "00:0d:3a:aa:00:0b"
        fake = FakeStore(
            store({"eth0": b, "eth1": a})["interfaces"], {"eth0": b, "eth1": a}
        )
        renamed = self._boot(fake, v1({"eth0": a, "eth1": b}))
        self.assertEqual(
            ["eth1", "eth0"], [item["name"] for item in renamed["config"]]
        )

    def test_other_datasources_are_renamed_as_before(self):
        netcfg = v2(AZURE)
        fake = mock.Mock()
        self.assertIs(netcfg, self._boot(fake, netcfg, dsname="NoCloud"))
        fake.load_store.assert_not_called()

    def test_init_renames_by_the_map_and_falls_back_on_error(self):
        from cloudinit.stages import Init

        init = Init.__new__(Init)
        init._distro = mock.Mock()
        init.datasource = mock.Mock(dsname="Azure")
        netcfg, mapped = v2(AZURE), {"version": 2, "ethernets": {}}
        with mock.patch.object(
            cc_vyos, "boot_interface_names", return_value=mapped
        ) as boot:
            init._apply_netcfg_names(netcfg)
        boot.assert_called_once_with(netcfg, "Azure")
        init.distro.apply_network_config_names.assert_called_once_with(mapped)

        init.distro.reset_mock()
        with mock.patch.object(
            cc_vyos, "boot_interface_names", side_effect=OSError("x")
        ):
            init._apply_netcfg_names(netcfg)
        init.distro.apply_network_config_names.assert_called_once_with(netcfg)
