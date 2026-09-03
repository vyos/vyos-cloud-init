# This file is part of cloud-init. See LICENSE file for license information.

from pathlib import Path

from cloudinit.config import cc_vyos_userdata
from tests.unittests.helpers import CiTestCase, mock


class TestVyosUserdata(CiTestCase):
    def test_get_tag_nodes_discovers_template_paths(self):
        templates_dir = Path(self.tmp_dir())
        (templates_dir / "interfaces" / "ethernet" / "node.tag").mkdir(
            parents=True
        )

        with mock.patch.object(
            cc_vyos_userdata, "TEMPLATES_DIR", str(templates_dir)
        ):
            self.assertEqual(
                [("interfaces", "ethernet")],
                cc_vyos_userdata.get_tag_nodes(),
            )

    def test_get_multi_nodes_accepts_trailing_metadata(self):
        templates_dir = Path(self.tmp_dir())
        multi_node = templates_dir / "system" / "name-server"
        ordinary_node = templates_dir / "system" / "host-name"
        multi_node.mkdir(parents=True)
        ordinary_node.mkdir(parents=True)
        (multi_node / "node.def").write_text(
            "multi: true\nhelp: System name server\n"
        )
        (ordinary_node / "node.def").write_text("help: Host name\n")

        with mock.patch.object(
            cc_vyos_userdata, "TEMPLATES_DIR", str(templates_dir)
        ):
            self.assertEqual(
                [("system", "name-server")],
                cc_vyos_userdata.get_multi_nodes(),
            )

    def test_string_to_command_parses_set_and_delete(self):
        self.assertEqual(
            {
                "cmd_action": "set",
                "cmd_path": ["system", "host-name"],
                "cmd_value": "edge-a",
            },
            cc_vyos_userdata.string_to_command(
                "set system host-name 'edge-a'"
            ),
        )
        self.assertEqual(
            {
                "cmd_action": "delete",
                "cmd_path": ["system", "name-server"],
                "cmd_value": "192.0.2.53",
            },
            cc_vyos_userdata.string_to_command(
                "delete system name-server '192.0.2.53'"
            ),
        )
        self.assertEqual(
            {
                "cmd_action": "delete",
                "cmd_path": ["system", "host-name"],
                "cmd_value": None,
            },
            cc_vyos_userdata.string_to_command("delete system host-name"),
        )

    def test_string_to_command_rejects_malformed_input(self):
        self.assertIsNone(cc_vyos_userdata.string_to_command("show version"))

    def test_apply_command_set_replaces_ordinary_node(self):
        config = mock.Mock()
        command = {
            "cmd_path": ["system", "host-name"],
            "cmd_value": "edge-a",
        }

        cc_vyos_userdata.apply_command_set(config, [], [], command)

        config.set.assert_called_once_with(
            ["system", "host-name"], "edge-a", replace=True
        )

        config.set_tag.assert_not_called()

    def test_apply_command_set_appends_multi_node_value(self):
        config = mock.Mock()
        command = {
            "cmd_path": ["system", "name-server"],
            "cmd_value": "192.0.2.53",
        }

        cc_vyos_userdata.apply_command_set(
            config, [], [("system", "name-server")], command
        )

        config.set.assert_called_once_with(
            ["system", "name-server"], "192.0.2.53", replace=False
        )

    def test_apply_command_set_preserves_nested_tag_node_values(self):
        config = mock.Mock()
        marked_paths = []
        config.set_tag.side_effect = lambda path: marked_paths.append(
            list(path)
        )
        command = {
            "cmd_path": [
                "vrf",
                "name",
                "customer",
                "protocols",
                "bgp",
                "address-family",
                "ipv4-unicast",
                "network",
            ],
            "cmd_value": "10.180.0.0/25",
        }
        tag_nodes = [
            ("vrf", "name"),
            (
                "vrf",
                "name",
                "node.tag",
                "protocols",
                "bgp",
                "address-family",
                "ipv4-unicast",
                "network",
            ),
        ]

        cc_vyos_userdata.apply_command_set(config, tag_nodes, [], command)

        config.set.assert_called_once_with(
            command["cmd_path"], "10.180.0.0/25", replace=False
        )
        self.assertEqual(
            [
                ["vrf", "name"],
                command["cmd_path"],
            ],
            marked_paths,
        )

    def test_apply_command_delete_uses_value_or_path(self):
        config = mock.Mock()

        cc_vyos_userdata.apply_command_delete(
            config,
            {
                "cmd_path": ["system", "name-server"],
                "cmd_value": "192.0.2.53",
            },
        )
        cc_vyos_userdata.apply_command_delete(
            config,
            {"cmd_path": ["system", "host-name"], "cmd_value": None},
        )

        config.delete_value.assert_called_once_with(
            ["system", "name-server"], "192.0.2.53"
        )
        config.delete.assert_called_once_with(["system", "host-name"])

    @mock.patch("cloudinit.config.cc_vyos_userdata.get_multi_nodes")
    @mock.patch("cloudinit.config.cc_vyos_userdata.get_tag_nodes")
    def test_apply_commands_routes_valid_commands_and_skips_malformed(
        self, tag_nodes, multi_nodes
    ):
        config = mock.Mock()
        tag_nodes.return_value = []
        multi_nodes.return_value = []

        cc_vyos_userdata.apply_commands(
            config,
            [
                "set system host-name 'edge-a'",
                "show version",
                "delete system name-server '192.0.2.53'",
                "delete system host-name",
            ],
        )

        config.set.assert_called_once_with(
            ["system", "host-name"], "edge-a", replace=True
        )
        config.delete_value.assert_called_once_with(
            ["system", "name-server"], "192.0.2.53"
        )
        config.delete.assert_called_once_with(["system", "host-name"])
