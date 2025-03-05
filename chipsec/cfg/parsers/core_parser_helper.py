# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2025, Intel Corporation
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# Contact information:
# chipsec@intel.com

import os
from chipsec.parsers import config_data
from chipsec.library.display import make_dict_hex
from chipsec.library.logger import logger

def config_convert_data(xml_node, did_is_range=False):
    INT_KEYS = ['dev', 'fun', 'vid', 'did', 'rid', 'offset',
                'bit', 'size', 'port', 'msr', 'value', 'address',
                'fixed_address', 'base_align', 'align_bits', 'mask',
                'reg_align', 'limit_align', 'regh_align', 'default', 
                'limit', 'enable_bit']
    BOOL_KEYS = ['req_pch']
    INT_LIST_KEYS = ['bus']
    STR_LIST_KEYS = ['config']
    RANGE_LIST_KEYS = ['detection_value']
    if did_is_range:
        INT_KEYS.remove('did')
        RANGE_LIST_KEYS.append('did')
    node_data = {}
    for key in xml_node.attrib:
        if key in INT_KEYS:
            node_data[key] = int(xml_node.attrib[key], 0)
        elif key in INT_LIST_KEYS:
            node_data[key] = [int(xml_node.attrib[key], 0)]
        elif key in STR_LIST_KEYS:
            node_data[key] = [x.strip() for x in xml_node.attrib[key].split(',')]
        elif key in RANGE_LIST_KEYS:
            node_data[key] = _get_range_data(xml_node, key)
        elif key in BOOL_KEYS:
            node_data[key] = xml_node.attrib[key].lower() == 'true'
        else:
            node_data[key] = xml_node.attrib[key]
    return node_data

def _get_range_data(xml_node, attr):
    int_items = []
    for item in xml_node.attrib[attr].split(','):
        item = item.strip()
        if item.upper().endswith('*'):
            x = int(item.replace('*', '0'), 0)
            int_items.extend(range(x, x + 0x10))
        elif '-' in item:
            item_min, item_max = item.split('-', 1)
            int_items.extend(range(int(item_min, 0), int(item_max, 0) + 1))
        else:
            int_items.append(int(item, 0))
    return int_items

class CoreParserHelper():
    def __init__(self, config):
        self.logger = logger()
        self.cfg = config

    def process_config_complex(self, stage_data, dev_name, dev_attr, component=None):
        ret_val = []

        attrs = {}
        if dev_attr.config:
            attrs['tmp'] = dev_attr.instances
            for fxml in dev_attr.config:
                cfg_file = fxml.replace('.', os.path.sep, fxml.count('.') - 1)
                cfg_path = os.path.join(os.path.dirname(stage_data.xml_file), cfg_file)
                ret_val.append(config_data(stage_data.vid_str, dev_name, cfg_path, component, attrs))

        return ret_val
    
    def handle_bars(self, et_node, stage_data, dest, cfg_obj):
        ret_val = []

        for bar in et_node.iter('bar'):
            ret_val.extend(self.handle_bar(bar, stage_data, dest, cfg_obj))
            
        return ret_val

    def handle_bar(self, et_node, stage_data, dest, cfg_obj):
        ret_val = []
        bus_attr = config_convert_data(et_node, True)
        if 'name' not in bus_attr or ('device' not in bus_attr and 'component' not in bus_attr):
            self.logger.log_debug(f"Missing 'name' or 'device' in {bus_attr}")
            return ret_val
        bar_name = bus_attr['name']
        dev_name = bus_attr['device'] = bus_attr['device'] if 'device' in bus_attr else bus_attr['component']
        self.process_bar(stage_data.vid_str, bar_name, bus_attr, dest, cfg_obj)
        # ret_val = (self._process_config(stage_data, dev_name, bus_attr))
        ret_val.extend(self.process_config_complex(stage_data, bar_name, dest[stage_data.vid_str][dev_name][bar_name], dev_name))
        hex_dict = make_dict_hex(bus_attr)
        self.logger.log_debug(f"    + {bus_attr['name']:16}: {hex_dict}")
        return ret_val
    
    def process_bar(self, vid_str, bar_name, bar_attr, dest, cfg_obj):
        if 'register' in bar_attr:
            bar_attr['register'] = self.make_reg_name(vid_str, bar_attr['device'], bar_attr['register'])
        if 'base_reg' in bar_attr:
            bar_attr['base_reg'] = self.make_reg_name(vid_str, bar_attr['device'], bar_attr['base_reg'])
        if 'mmio_base' in bar_attr:
            bar_attr['mmio_base'] = self.make_reg_name(vid_str, bar_attr['device'], bar_attr['mmio_base'])
        if 'limit_register' in bar_attr:
            bar_attr['limit_register'] = self.make_reg_name(vid_str, bar_attr['device'], bar_attr['limit_register'])

        if vid_str not in dest:
            dest[vid_str] = {}
        if bar_attr['device'] not in dest[vid_str]:
            dest[vid_str][bar_attr['device']] = {}
        if bar_name in dest[vid_str][bar_attr['device']] and 'config' in bar_attr:
            dest[vid_str][bar_attr['device']][bar_name].add_config(bar_attr['config'])
        else:
            bar_attr['ids'] = self.cfg.CONFIG_PCI[vid_str][bar_attr['device']].instances.values()
            bar_obj = cfg_obj(bar_attr)
            dest[vid_str][bar_attr['device']][bar_name] = bar_obj

    def make_reg_name(self, vid_str, device_name, reg_name):
        return '.'.join([vid_str, device_name, reg_name])