# vi: ts=4 expandtab
#
#    Copyright (C) 2020 Sentrium S.L.
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
from pathlib import Path
from cloudinit import log as logging
from cloudinit.settings import PER_INSTANCE
try:
    from vyos.configtree import ConfigTree
except ImportError as err:
    print(f'The module cannot be imported: {err}')

# configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

frequency = PER_INSTANCE
# path to templates directory, required for analyzing nodes
TEMPLATES_DIR = '/opt/vyatta/share/vyatta-cfg/templates/'
# VyOS configuration files
CFG_FILE_MAIN = '/opt/vyatta/etc/config/config.boot'
CFG_FILE_DEFAULT = '/opt/vyatta/etc/config.boot.default'


# get list of all tag nodes
def get_tag_nodes():
    try:
        logger.debug("Searching for tag nodes in configuration templates")
        tag_nodes = []
        # search for node.tag directories
        node_tag_dirs = Path(TEMPLATES_DIR).rglob('node.tag')
        # add each found directory to tag nodes list
        for node_tag in node_tag_dirs:
            current_node_path = node_tag.relative_to(TEMPLATES_DIR).parent.parts
            tag_nodes.append(current_node_path)
        logger.debug("Tag nodes: {}".format(tag_nodes))
        return tag_nodes
    except Exception as err:
        logger.error("Failed to find tag nodes: {}".format(err))


# get list of all multi nodes
def get_multi_nodes():
    try:
        logger.debug("Searching for multi nodes in configuration templates")
        multi_nodes = []
        # search for node.def files
        node_def_files = Path(TEMPLATES_DIR).rglob('node.def')
        # prepare filter to match multi node files
        regex_filter = re.compile(r'^multi:.*$', re.MULTILINE)
        # add each node.def with multi mark to list
        for node_def_file in node_def_files:
            file_content = node_def_file.read_text()
            if regex_filter.search(file_content):
                current_multi_path = node_def_file.relative_to(
                    TEMPLATES_DIR).parent.parts
                multi_nodes.append(current_multi_path)
        logger.debug("Multi nodes: {}".format(multi_nodes))
        return multi_nodes
    except Exception as err:
        logger.error("Failed to find multi nodes: {}".format(err))


# check if a node is inside a list of nodes
def inside_nodes_list(node_path, nodes_list):
    match = False
    # compare with all items in list
    for list_item in nodes_list:
        # continue only if lengths are equal
        if len(list_item) == len(node_path):
            # match parts of nodes paths one by one
            for element_id in list(range(len(node_path))):
                # break is items does not match
                if not (node_path[element_id] == list_item[element_id] or
                        list_item[element_id] == 'node.tag'):
                    break
                # match as tag node only if both nodes have the same length
                elif ((node_path[element_id] == list_item[element_id] or
                       list_item[element_id] == 'node.tag') and
                      element_id == len(node_path) - 1):
                    match = True
        # break if we have a match
        if match is True:
            break
    return match


# convert string to command (action + path + value)
def string_to_command(stringcmd):
    # regex to split string to action + path + value
    regex_filter = re.compile(
        r'^(?P<cmd_action>set|delete) (?P<cmd_path>[^\']+)( \'(?P<cmd_value>.*)\')*$'
    )
    if regex_filter.search(stringcmd):
        # command structure
        command = {
            'cmd_action':
                regex_filter.search(stringcmd).group('cmd_action'),
            'cmd_path':
                regex_filter.search(stringcmd).group('cmd_path').split(),
            'cmd_value':
                regex_filter.search(stringcmd).group('cmd_value')
        }
        return command
    else:
        return None


# helper: mark nodes as tag in config, if this is necessary
def mark_tag(config, node_path, tag_nodes):
    current_node_path = []
    # check and mark each element in command path if necessary
    for current_node in node_path:
        current_node_path.append(current_node)
        if inside_nodes_list(current_node_path, tag_nodes):
            logger.debug(
                "Marking node as tag: \"{}\"".format(current_node_path))
            config.set_tag(current_node_path)


# apply "set" command
def apply_command_set(config, tag_nodes, multi_nodes, command):
    # if a node is multi type add value instead replacing
    replace_option = not inside_nodes_list(command['cmd_path'], multi_nodes)
    if not replace_option:
        logger.debug("{} is a multi node, adding value".format(
            command['cmd_path']))

    config.set(command['cmd_path'],
               command['cmd_value'],
               replace=replace_option)

    # mark configured nodes as tag, if this is necessary
    mark_tag(config, command['cmd_path'], tag_nodes)


# apply "delete" command
def apply_command_delete(config, command):
    # delete a value
    if command['cmd_value']:
        config.delete_value(command['cmd_path'], command['cmd_value'])
    # otherwise delete path
    else:
        config.delete(command['cmd_path'])


# apply command
def apply_commands(config, commands_list):
    # get all tag and multi nodes
    tag_nodes = get_tag_nodes()
    multi_nodes = get_multi_nodes()

    # roll through configration commands
    for command_line in commands_list:
        # convert command to format, appliable to configuration
        command = string_to_command(command_line)
        # if conversion is successful, apply the command
        if command:
            logger.debug("Configuring command: \"{}\"".format(command_line))
            try:
                if command['cmd_action'] == 'set':
                    apply_command_set(config, tag_nodes, multi_nodes, command)
                if command['cmd_action'] == 'delete':
                    apply_command_delete(config, command)
            except Exception as err:
                logger.error("Unable to configure command: {}".format(err))


# main config handler
def handle(name, cfg, cloud, log, _args):
    # Get commands list to configure
    commands_list = cfg.get('vyos_config_commands', [])
    logger.debug("Commands to configure: {}".format(commands_list))

    if commands_list:
        # open configuration file
        if Path(CFG_FILE_MAIN).exists():
            config_file_path = CFG_FILE_MAIN
        else:
            config_file_path = CFG_FILE_DEFAULT

        logger.debug("Using configuration file: {}".format(config_file_path))
        with open(config_file_path, 'r') as f:
            config_file = f.read()
        # load a file content into a config object
        config = ConfigTree(config_file)

        # Add configuration from the vyos_config_commands cloud-config section
        try:
            apply_commands(config, commands_list)
        except Exception as err:
            logger.error(
                "Failed to apply configuration commands: {}".format(err))

        # save a new configuration file
        try:
            with open(config_file_path, 'w') as f:
                f.write(config.to_string())
            logger.debug(
                "Configuration file saved: {}".format(config_file_path))
        except Exception as err:
            logger.error("Failed to write config into the file {}: {}".format(
                config_file_path, err))
