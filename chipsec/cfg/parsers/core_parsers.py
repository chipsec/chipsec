# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2023, Intel Corporation
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

import copy
from chipsec.parsers import BaseConfigParser
from chipsec.parsers import Stage
from chipsec.parsers import info_data

CONFIG_TAG = 'configuration'


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


def _config_convert_data(xml_node, did_is_range=False):
    INT_KEYS = ['dev', 'fun', 'vid', 'did', 'rid', 'offset',
                'bit', 'size', 'port', 'msr', 'value', 'address',
                'fixed_address', 'base_align', 'align_bits', 'mask',
                'reg_align', 'limit_align', 'regh_align',
                'width', 'reg']
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


class PlatformInfo(BaseConfigParser):
    def get_metadata(self):
        return {'info': self.handle_info}

    def get_stage(self):
        return Stage.GET_INFO

    def handle_info(self, et_node, stage_data):
        platform = ''
        req_pch = None
        family = None
        proc_code = None
        pch_code = None
        detect_vals = []
        sku_data = []
        vid_int = int(stage_data.vid_str, 16)

        # Extract platform information. If no platform found it is just a device entry.
        cfg_info = _config_convert_data(stage_data.configuration)
        if 'platform' in cfg_info:
            platform = cfg_info['platform']
        if 'req_pch' in cfg_info:
            req_pch = cfg_info['req_pch']
        if platform and platform.lower().startswith('pch'):
            pch_code = platform.upper()
        else:
            proc_code = platform.upper()

        # Start processing the <info> tag
        for info in et_node.iter('info'):
            cfg_info = _config_convert_data(info)
            if 'family' in cfg_info:
                family = cfg_info['family']
            if 'detection_value' in cfg_info:
                detect_vals = cfg_info['detection_value']
            for sku in info.iter('sku'):
                sku_info = _config_convert_data(sku, True)
                if 'code' not in sku_info or sku_info['code'] != platform.upper():
                    sku_info['code'] = platform.upper()
                if 'vid' not in sku_info:
                    sku_info['vid'] = vid_int
                sku_data.append(sku_info)

        return info_data(family, proc_code, pch_code, detect_vals, req_pch, stage_data.vid_str, sku_data)


class CoreConfig(BaseConfigParser):
    def get_metadata(self):
        return {'pci': self.handle_pci,
                'mmio': self.handle_mmio,
                'io': self.handle_io,
                'ima': self.handle_ima,
                'memory': self.handle_memory,
                'registers': self.handle_registers,
                'controls': self.handle_controls,
                'locks': self.handle_locks}

    def get_stage(self):
        return Stage.DEVICE_CFG

    def _process_pci_dev(self, vid_str, dev_name, dev_attr):
        device_added = False
        if 'did' in dev_attr:
            for did in dev_attr['did']:
                did_str = self.cfg._make_hex_key_str(did)
                if did_str in self.cfg.CONFIG_PCI_RAW[vid_str]:
                    pci_data = self.cfg.CONFIG_PCI_RAW[vid_str][did_str]
                    self._add_dev(vid_str, dev_name, pci_data, dev_attr)
                    device_added = True
                    break
        else:
            for did_str in self.cfg.CONFIG_PCI_RAW[vid_str]:
                pci_data = self.cfg.CONFIG_PCI_RAW[vid_str][did_str]
                
                if dev_attr['bus'] in pci_data['bus'] and dev_attr['dev'] == pci_data['dev'] and \
                   dev_attr['fun'] == pci_data['fun']:
                    self._add_dev(vid_str, dev_name, pci_data, dev_attr)
                    device_added = True
                    break
        if not device_added:
            self._add_dev(vid_str, dev_name, None, dev_attr)

    def _add_dev(self, vid_str, name, pci_info, dev_attr):
        if pci_info:
            self.cfg.BUS[name] = pci_info['bus']
            self.cfg.CONFIG_PCI[name] = copy.copy(pci_info)
        else:
            self.cfg.CONFIG_PCI[name] = copy.deepcopy(dev_attr)
            self.cfg.BUS[name] = []
            if 'did' in dev_attr:
                self.cfg.CONFIG_PCI[name]['did'] = dev_attr['did'][0]

    def handle_pci(self, et_node, stage_data):
        ret_val = []

        for dev in et_node.iter('device'):
            dev_attr = _config_convert_data(dev, True)
            if 'name' not in dev_attr:
                continue
            dev_name = dev_attr['name']
            self._process_pci_dev(stage_data.vid_str, dev_name, dev_attr)
            self.logger.log_debug(f"    + {dev_attr['name']:16}: {dev_attr}")

        return ret_val

    def handle_controls(self, et_node, stage_data):
        return self._add_entry_simple(self.cfg.CONTROLS, stage_data, et_node, 'control')

    def handle_io(self, et_node, stage_data):
        return self._add_entry_simple(self.cfg.IO_BARS, stage_data, et_node, 'bar')

    def handle_ima(self, et_node, stage_data):
        return self._add_entry_simple(self.cfg.IMA_REGISTERS, stage_data, et_node, 'indirect')

    def handle_locks(self, et_node, stage_data):
        return self._add_entry_simple(self.cfg.LOCKS, stage_data, et_node, 'lock')

    def handle_memory(self, et_node, stage_data):
        return self._add_entry_simple(self.cfg.MEMORY_RANGES, stage_data, et_node, 'range')

    def handle_mmio(self, et_node, stage_data):
        return self._add_entry_simple(self.cfg.MMIO_BARS, stage_data, et_node, 'bar')

    def handle_registers(self, et_node, stage_data):
        ret_val = []
        dest = self.cfg.REGISTERS
        for reg in et_node.iter('register'):
            reg_attr = _config_convert_data(reg)
            if 'name' not in reg_attr:
                self.logger.log_error(f'Missing name entry for {reg_attr}')
                continue
            reg_name = reg_attr['name']
            if 'undef' in reg_attr:
                if reg_name in dest:
                    self.logger.log_debug(f"    - {reg_name:16}: {reg_attr['undef']}")
                    dest.pop(reg_name, None)
                continue

            # Patch missing or incorrect data
            if 'desc' not in reg_attr:
                reg_attr['desc'] = reg_name
            if 'size' not in reg_attr:
                self.logger.log_debug(f'Missing size entry for {reg_name:16}: {reg_attr}. Assuming 4 bytes')
                reg_attr['size'] = 4

            # Get existing field data
            if reg_name in self.cfg.REGISTERS:
                reg_fields = self.cfg.REGISTERS[reg_name]['FIELDS']
            else:
                reg_fields = {}

            for field in reg.iter('field'):
                field_attr = _config_convert_data(field)
                field_name = field_attr['name']

                # Locked by attributes need to be handled here due to embedding information in field data
                if 'lockedby' in field_attr:
                    lockedby = field_attr['lockedby']
                    if lockedby in self.cfg.LOCKEDBY:
                        self.cfg.LOCKEDBY[lockedby].append({reg_name, field_name})
                    else:
                        self.cfg.LOCKEDBY[lockedby] = [{reg_name, field_name}]
                # Handle rest of field data here
                if 'desc' not in field_attr:
                    field_attr['desc'] = field_name
                reg_fields[field_name] = field_attr

            # Store all register data
            reg_attr['FIELDS'] = reg_fields
            self.cfg.REGISTERS[reg_name] = reg_attr
            self.logger.log_debug(f'    + {reg_name:16}: {reg_attr}')
        return ret_val

    def _add_entry_simple(self, dest, stage_data, et_node, node_name):
        ret_val = []
        for node in et_node.iter(node_name):
            attrs = _config_convert_data(node)
            if 'name' not in attrs:
                self.logger.log_error(f'Missing name entry for {attrs}')
                continue
            if 'undef' in attrs:
                if attrs['name'] in dest:
                    self.logger.log_debug(f"    - {attrs['name']:16}: {attrs['undef']}")
                    dest.pop(attrs['name'], None)
                continue
            if 'desc' not in attrs:
                attrs['desc'] = attrs['name']
            dest[attrs['name']] = attrs
            self.logger.log_debug(f"    + {attrs['name']:16}: {attrs}")
        return ret_val


parsers = [PlatformInfo, CoreConfig]
