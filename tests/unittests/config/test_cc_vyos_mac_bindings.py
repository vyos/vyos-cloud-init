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


# Azure, four NICs: the names cloud-init gives them, in the order Azure
# lists them, and the MAC of each - measured on a fresh deployment
AZURE = {
    "eth0": "00:0D:3A:47:38:1D",
    "eth1": "00:0D:3A:47:3B:29",
    "eth2": "00:0D:3A:47:33:AD",
    "eth3": "00:0D:3A:47:3B:F8",
}


def key(mac):
    return "ID_NET_NAME_MAC=enx" + mac.lower().replace(":", "")


class TestMacBindings(CiTestCase):
    def setUp(self):
        super().setUp()
        cc_vyos.mac_bindings.clear()

    def test_azure_on_a_map_image_records_no_hw_id(self):
        config = FakeConfig()
        with mock.patch.object(cc_vyos, "use_interface_map", True):
            cc_vyos.set_ether_mac(config, "eth0", AZURE["eth0"])
        self.assertEqual([], config.set_calls)
        self.assertEqual({"eth0": "00:0d:3a:47:38:1d"}, cc_vyos.mac_bindings)

    def test_other_platforms_keep_hw_id(self):
        # the map is written on Azure only; elsewhere is an open question
        config = FakeConfig()
        with mock.patch.object(cc_vyos, "use_interface_map", False):
            cc_vyos.set_ether_mac(config, "eth0", AZURE["eth0"])
        self.assertEqual(
            [(["interfaces", "ethernet", "eth0", "hw-id"], AZURE["eth0"])],
            config.set_calls,
        )
        self.assertEqual({}, cc_vyos.mac_bindings)

    def test_network_config_v2_match_records_a_binding_on_azure(self):
        config = FakeConfig()
        with mock.patch.object(
            cc_vyos, "use_interface_map", True
        ), mock.patch.object(cc_vyos, "config_net_v2_common"):
            cc_vyos.config_net_v2_ethernet(
                config, "eth1", {"match": {"macaddress": AZURE["eth1"]}}
            )
        self.assertEqual({"eth1": "00:0d:3a:47:3b:29"}, cc_vyos.mac_bindings)
        self.assertEqual([], config.set_calls)

    def test_bindings_become_map_entries(self):
        fake = FakeStore()
        bindings = {n: m.lower() for n, m in AZURE.items()}
        with mock.patch.object(
            cc_vyos, "ifname_store", fake
        ), mock.patch.object(
            cc_vyos, "present_macs", return_value=set(bindings.values())
        ):
            cc_vyos.save_mac_bindings(bindings)
        self.assertEqual(key(AZURE["eth0"]), fake.saved["interfaces"]["eth0"])
        self.assertEqual("00:0d:3a:47:38:1d", fake.saved["hardware"]["eth0"])
        self.assertEqual(4, len(fake.saved["interfaces"]))

    def test_a_name_on_a_nic_still_present_is_kept(self):
        fake = FakeStore(
            {"eth0": key("00:0d:3a:48:00:00")}, {"eth0": "00:0d:3a:48:00:00"}
        )
        with mock.patch.object(
            cc_vyos, "ifname_store", fake
        ), mock.patch.object(
            cc_vyos, "present_macs", return_value={"00:0d:3a:48:00:00"}
        ):
            cc_vyos.save_mac_bindings({"eth0": "00:0d:3a:47:38:1d"})
        self.assertEqual(
            key("00:0d:3a:48:00:00"), fake.saved["interfaces"]["eth0"]
        )

    def test_a_rerun_after_an_adoption_moves_nothing(self):
        # measured on 5479.0.8: after LAN2's NIC was re-created and adopted
        # as eth2, Azure lists it last. cloud-init runs again on the next new
        # instance (an image upgrade); the names the NICs have must hold
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
        fake = FakeStore({n: key(m) for n, m in names.items()}, names)
        with mock.patch.object(
            cc_vyos, "ifname_store", fake
        ), mock.patch.object(
            cc_vyos, "present_macs", return_value=set(names.values())
        ):
            cc_vyos.save_mac_bindings(imds)
        self.assertEqual(
            {n: key(m) for n, m in names.items()}, fake.saved["interfaces"]
        )
        self.assertNotIn("absent", fake.saved)

    def test_a_vacant_name_whose_nic_has_another_name_is_kept_from_new_nics(
        self,
    ):
        # a VM rebuilt from its disk: the old WAN NIC is gone, LAN1's NIC is
        # now listed first, plus a new NIC. Which name LAN1's NIC should have
        # is not known here; eth0 must not go to the new NIC (FR-1), so it is
        # recorded as missing and the next boot leaves it reserved
        old_wan, lan1, new = (
            "00:0d:3a:aa:00:0a",
            "00:0d:3a:aa:00:0b",
            "60:45:bd:00:00:01",
        )
        fake = FakeStore(
            {"eth0": key(old_wan), "eth1": key(lan1)},
            {"eth0": old_wan, "eth1": lan1},
        )
        with mock.patch.object(
            cc_vyos, "ifname_store", fake
        ), mock.patch.object(
            cc_vyos, "present_macs", return_value={lan1, new}
        ), mock.patch.object(
            cc_vyos.logger, "warning"
        ) as warning:
            cc_vyos.save_mac_bindings({"eth0": lan1, "eth1": new})
        self.assertEqual(
            {"eth0": key(old_wan), "eth1": key(lan1)}, fake.saved["interfaces"]
        )
        self.assertEqual(["eth0"], fake.saved["absent"])
        warning.assert_called_once()
        self.assertIn("eth0", warning.call_args[0][0])

    def test_a_lone_nic_keyed_on_its_path_is_known_by_its_address(self):
        # two NICs, the primary removed: the survivor ran alone as eth1, so
        # its key is the shared VMBus path. An upgrade runs cloud-init again
        # with Azure listing it as eth0 - it must not also become eth0 and
        # run the removed primary's configuration (FR3-1)
        primary, lone = "00:0d:3a:aa:00:0a", "00:0d:3a:aa:00:0b"
        fake = FakeStore(
            {"eth0": key(primary), "eth1": "ID_PATH=acpi-MSFT1000:00"},
            {"eth0": primary, "eth1": lone},
        )
        with mock.patch.object(
            cc_vyos, "ifname_store", fake
        ), mock.patch.object(cc_vyos, "present_macs", return_value={lone}):
            cc_vyos.save_mac_bindings({"eth0": lone})
        self.assertEqual(key(primary), fake.saved["interfaces"]["eth0"])
        self.assertEqual(
            "ID_PATH=acpi-MSFT1000:00", fake.saved["interfaces"]["eth1"]
        )
        self.assertEqual(["eth0"], fake.saved["absent"])

    def test_a_contested_name_is_added_to_the_names_already_missing(self):
        old_wan, lan1, gone = (
            "00:0d:3a:aa:00:0a",
            "00:0d:3a:aa:00:0b",
            "00:0d:3a:aa:00:0c",
        )
        fake = FakeStore(
            {"eth0": key(old_wan), "eth1": key(lan1), "eth3": key(gone)},
            {"eth0": old_wan, "eth1": lan1, "eth3": gone},
        )
        fake.store["absent"] = ["eth3"]
        with mock.patch.object(
            cc_vyos, "ifname_store", fake
        ), mock.patch.object(cc_vyos, "present_macs", return_value={lan1}):
            cc_vyos.save_mac_bindings({"eth0": lan1})
        self.assertEqual(["eth0", "eth3"], fake.saved["absent"])

    def test_a_name_with_no_recorded_address_is_kept(self):
        # nothing on record to say its NIC is gone
        fake = FakeStore({"eth1": key("00:0d:3a:aa:00:0b")})
        with mock.patch.object(
            cc_vyos, "ifname_store", fake
        ), mock.patch.object(
            cc_vyos, "present_macs", return_value={"00:0d:3a:aa:00:0c"}
        ):
            cc_vyos.save_mac_bindings({"eth1": "00:0d:3a:aa:00:0c"})
        self.assertEqual(
            key("00:0d:3a:aa:00:0b"), fake.saved["interfaces"]["eth1"]
        )

    def test_a_name_not_in_the_map_is_neither_warned_about_nor_reserved(self):
        lan1 = "00:0d:3a:aa:00:0b"
        fake = FakeStore({"eth1": key(lan1)}, {"eth1": lan1})
        with mock.patch.object(
            cc_vyos, "ifname_store", fake
        ), mock.patch.object(
            cc_vyos, "present_macs", return_value={lan1}
        ), mock.patch.object(
            cc_vyos.logger, "warning"
        ) as warning:
            cc_vyos.save_mac_bindings({"eth0": lan1})
        self.assertNotIn("eth0", fake.saved["interfaces"])
        self.assertNotIn("absent", fake.saved)
        warning.assert_not_called()

    def test_a_disk_on_new_nics_takes_the_platform_names(self):
        # restore as a new VM: every recorded NIC is gone, and this runs once
        # for the new instance with the order Azure lists the new NICs in
        old = {n: "00:0d:3a:48:00:0" + n[-1] for n in AZURE}
        fake = FakeStore({n: key(m) for n, m in old.items()}, old)
        bindings = {n: m.lower() for n, m in AZURE.items()}
        with mock.patch.object(
            cc_vyos, "ifname_store", fake
        ), mock.patch.object(
            cc_vyos, "present_macs", return_value=set(bindings.values())
        ):
            cc_vyos.save_mac_bindings(bindings)
        self.assertEqual(
            {n: key(m) for n, m in AZURE.items()}, fake.saved["interfaces"]
        )

    def test_a_mac_is_never_given_two_names(self):
        fake = FakeStore(
            {"eth5": key(AZURE["eth0"])}, {"eth5": AZURE["eth0"].lower()}
        )
        with mock.patch.object(
            cc_vyos, "ifname_store", fake
        ), mock.patch.object(
            cc_vyos, "present_macs", return_value={AZURE["eth0"].lower()}
        ):
            cc_vyos.save_mac_bindings({"eth0": AZURE["eth0"].lower()})
        self.assertNotIn("eth0", fake.saved["interfaces"])

    def test_unmounted_volume_writes_nothing(self):
        fake = FakeStore(mounted=False)
        with mock.patch.object(
            cc_vyos, "ifname_store", fake
        ), mock.patch.object(cc_vyos, "present_macs", return_value=set()):
            cc_vyos.save_mac_bindings({"eth0": "00:0d:3a:47:38:1d"})
        self.assertIsNone(fake.saved)

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

    def test_a_broken_import_on_a_map_image_is_reported_not_hidden(self):
        # the image has the map, so hw-id would be rejected: the bindings are
        # not written as hw-id either, and the failure is logged
        with mock.patch.object(
            cc_vyos, "ifname_store", None
        ), mock.patch.object(cc_vyos.logger, "error") as error:
            cc_vyos.save_mac_bindings({"eth0": "00:0d:3a:47:38:1d"})
        error.assert_called_once()
        self.assertIn("eth0", error.call_args[0][0])

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

    def test_the_bindings_are_saved_after_the_configuration(self):
        config = mock.Mock()
        config.to_string.return_value = "interfaces {}\n"
        path = self.tmp_path("config.boot")
        with mock.patch.object(cc_vyos, "save_mac_bindings") as save:
            self.assertTrue(cc_vyos.write_config(config, path))
        save.assert_called_once_with(cc_vyos.mac_bindings)
        with open(path) as f:
            self.assertEqual("interfaces {}\n", f.read())

    def test_no_bindings_without_the_configuration(self):
        config = mock.Mock()
        config.to_string.return_value = "interfaces {}\n"
        path = self.tmp_path("missing-dir/config.boot")
        with mock.patch.object(cc_vyos, "save_mac_bindings") as save:
            self.assertFalse(cc_vyos.write_config(config, path))
        save.assert_not_called()
