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
import os
from chipsec.cfg.parsers.ip.iobar import IOBarConfig
from chipsec.cfg.parsers.ip.io import IOConfig
from chipsec.cfg.parsers.ip.memory import MemoryConfig
from chipsec.cfg.parsers.ip.mmio_bar import MMIOBarConfig
from chipsec.cfg.parsers.ip.mm_msgbus import MM_MSGBUSConfig
from chipsec.cfg.parsers.ip.msgbus import MSGBUSConfig
from chipsec.cfg.parsers.ip.msr import MSRConfig
from chipsec.cfg.parsers.ip.pci_device import PCIConfig
from chipsec.cfg.parsers.registers.controls import CONTROLHelper
from chipsec.cfg.parsers.registers.io import IORegisters
from chipsec.cfg.parsers.registers.iobar import IOBARRegisters
from chipsec.cfg.parsers.registers.memory import MEMORYRegisters
from chipsec.cfg.parsers.registers.mm_msgbus import MM_MSGBUSRegisters
from chipsec.cfg.parsers.registers.mmcfg import MMCFGRegisters
from chipsec.cfg.parsers.registers.mmio import MMIORegisters
from chipsec.cfg.parsers.registers.msgbus import MSGBUSRegisters
from chipsec.cfg.parsers.registers.msr import MSRRegisters
from chipsec.cfg.parsers.registers.pci import PCIRegisters
from chipsec.cfg.parsers.registers.locks import LOCKSHelper
from chipsec.parsers import BaseConfigParser
from chipsec.parsers import Stage
from chipsec.parsers import info_data, config_data
from chipsec.library.display import make_dict_hex

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
    # INT_KEYS = ['dev', 'fun', 'vid', 'did', 'rid', 'offset',
    #             'bit', 'size', 'port', 'msr', 'value', 'address',
    #             'fixed_address', 'base_align', 'align_bits', 'mask',
    #             'reg_align', 'limit_align', 'regh_align',
    #             'width', 'reg']
    INT_KEYS = ['dev', 'fun', 'vid', 'did', 'rid', 'offset',
                'bit', 'size', 'port', 'msr', 'value', 'address',
                'fixed_address', 'base_align', 'align_bits', 'mask',
                'reg_align', 'limit_align', 'regh_align', 'default']
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
        req_pch = False
        family = None
        proc_code = None
        pch_code = None
        dev_code = None
        device = None
        detect_vals = []
        sku_data = []
        vid_int = int(stage_data.vid_str, 16)

        # Extract platform information. If no platform found it is just a device entry.
        cfg_info = _config_convert_data(stage_data.configuration)
        if 'platform' in cfg_info:
            platform = cfg_info['platform']
        if 'req_pch' in cfg_info:
            req_pch = cfg_info['req_pch']
        if 'device' in cfg_info:
            device = cfg_info['device']
        if device:
            dev_code = device.upper()
        elif platform and platform.lower().startswith('pch'):
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
                sku_info = _config_convert_data(sku)
                if 'code' not in sku_info:
                    if platform:
                        sku_info['code'] = platform.upper()
                    elif device:
                        sku_info['code'] = device.upper()
                if 'vid' not in sku_info:
                    sku_info['vid'] = vid_int
                sku_data.append(sku_info)

        return info_data(family, proc_code, pch_code, dev_code, detect_vals, req_pch, stage_data.vid_str, sku_data)



class DevConfig(BaseConfigParser):
    def get_metadata(self):
        return {'pci': self.handle_pci,
                'memory': self.handle_memory,
                'mm_msgbus': self.handle_mm_msgbus,
                'msgbus': self.handle_msgbus,
                'io': self.handle_io,
                'msr': self.handle_msr,
                'mmiobar': self.handle_mmiobar,
                'iobar': self.handle_iobar}

    def get_stage(self):
        return Stage.DEVICE_CFG

    def _process_pci_dev(self, vid_str, dev_name, dev_attr):
        if 'did' in dev_attr:
            for did in dev_attr['did']:
                did_str = self.cfg._make_hex_key_str(did)
                if vid_str in self.cfg.CONFIG_PCI_RAW and did_str in self.cfg.CONFIG_PCI_RAW[vid_str]:
                    cfg_data = self.cfg.CONFIG_PCI_RAW[vid_str][did_str]
                    self._add_dev(vid_str, dev_name, cfg_data, dev_attr)
                    break
        else:
            if vid_str in self.cfg.CONFIG_PCI_RAW:
                for did_str in self.cfg.CONFIG_PCI_RAW[vid_str]:
                    for pci_data in self.cfg.CONFIG_PCI_RAW[vid_str][did_str].instances.values():
                        if any(b == pci_data.bus for b in dev_attr['bus']) and dev_attr['dev'] == pci_data.dev and \
                        dev_attr['fun'] == pci_data.fun:
                            cfg_data = self.cfg.CONFIG_PCI_RAW[vid_str][did_str]
                            self._add_dev(vid_str, dev_name, cfg_data, dev_attr)
                            break
        if dev_name not in self.cfg.CONFIG_PCI[vid_str]:
            self._add_dev(vid_str, dev_name, None, dev_attr)

    def _add_dev(self, vid_str, name, pci_info, dev_attr):
        if name not in self.cfg.CONFIG_PCI[vid_str]:
            for key in ['MMIO_BARS', 'IO_BARS', 'REGISTERS']:
                node = getattr(self.cfg, key)
                if name not in node[vid_str]:
                    node[vid_str][name] = {}
        if pci_info:
            pci_info.update_name(name)
            if 'config' in dev_attr:
                pci_info.add_config(dev_attr['config'])
            self.cfg.CONFIG_PCI[vid_str][name] = pci_info
        else:
            dev_attr['bus'] = None
            if 'did' in dev_attr:
                dev_attr['did'] = dev_attr['did'][0]
            dev_attr['name'] = name
            pci_obj = PCIConfig(dev_attr)
            if 'config' in dev_attr:
                pci_obj.add_config(dev_attr['config'])
            self.cfg.CONFIG_PCI[vid_str][name] = pci_obj

    def _make_reg_name(self, vid_str, device_name, reg_name):
        return '.'.join([vid_str, device_name, reg_name])
    
    def _process_bar(self, vid_str, bar_name, bar_attr, dest, cfg_obj):
        if 'register' in bar_attr:
            bar_attr['register'] = self._make_reg_name(vid_str, bar_attr['device'], bar_attr['register'])
        if 'base_reg' in bar_attr:
            bar_attr['base_reg'] = self._make_reg_name(vid_str, bar_attr['device'], bar_attr['base_reg'])
        if 'mmio_base' in bar_attr:
            bar_attr['mmio_base'] = self._make_reg_name(vid_str, bar_attr['device'], bar_attr['mmio_base'])
        if 'limit_register' in bar_attr:
            bar_attr['limit_register'] = self._make_reg_name(vid_str, bar_attr['device'], bar_attr['limit_register'])

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

    def _process_def(self, dest, et_node, tag, stage_data, cfg_obj):
        ret_val = []
        vid_str = stage_data.vid_str

        for node in et_node.iter(tag):
            node_attr = _config_convert_data(node)
            if 'name' not in node_attr or 'config' not in node_attr:
                continue
            dev_name = node_attr['name']
            if dev_name not in dest[vid_str]:
                print(dest, cfg_obj)
                new_obj = cfg_obj(copy.deepcopy(node_attr))
                dest[vid_str][dev_name] = new_obj
            else:
                mobj = dest[vid_str][dev_name]
                mobj.add_config(node_attr['config'])
            ret_val.extend(self._process_config(stage_data, dev_name, node_attr))
            hex_dict = make_dict_hex(node_attr)
            self.logger.log_debug(f"    + {node_attr['name']:16}: {hex_dict}")

        return ret_val

    def _process_config(self, stage_data, dev_name, dev_attr):
        ret_val = []

        attrs = {}
        if 'config' in dev_attr:
            component = dev_attr.get('component', None)
            for attr in dev_attr.keys():
                if attr not in ['config', 'name']:
                    attrs[attr] = dev_attr[attr]
            for fxml in dev_attr['config']:
                cfg_file = fxml.replace('.', os.path.sep, fxml.count('.') - 1)
                cfg_path = os.path.join(os.path.dirname(stage_data.xml_file), cfg_file)
                ret_val.append(config_data(stage_data.vid_str, dev_name, cfg_path, component, attrs))

        return ret_val

    def _process_config_complex(self, stage_data, dev_name, dev_attr, component=None):
        ret_val = []

        attrs = {}
        if dev_attr.config:
            attrs['tmp'] = dev_attr.instances
            for fxml in dev_attr.config:
                cfg_file = fxml.replace('.', os.path.sep, fxml.count('.') - 1)
                cfg_path = os.path.join(os.path.dirname(stage_data.xml_file), cfg_file)
                ret_val.append(config_data(stage_data.vid_str, dev_name, cfg_path, component, attrs))

        return ret_val

    def handle_pci(self, et_node, stage_data):
        ret_val = []

        for dev in et_node.iter('device'):
            dev_attr = _config_convert_data(dev, True)
            if 'name' not in dev_attr:
                continue
            dev_name = dev_attr['name']
            self._process_pci_dev(stage_data.vid_str, dev_name, dev_attr)
            ret_val.extend(self._process_config_complex(stage_data, dev_name, self.cfg.CONFIG_PCI[stage_data.vid_str][dev_name]))
            hex_dict = make_dict_hex(dev_attr)
            self.logger.log_debug(f"    + {dev_attr['name']:16}: {hex_dict}")
        return ret_val

    def handle_memory(self, et_node, stage_data):
        return self._process_def(self.cfg.MEMORY_RANGES, et_node, 'range', stage_data, MemoryConfig)

    def handle_mm_msgbus(self, et_node, stage_data):
        return self._process_def(self.cfg.MM_MSGBUS, et_node, 'definition', stage_data, MM_MSGBUSConfig)

    def handle_msgbus(self, et_node, stage_data):
        return self._process_def(self.cfg.MSGBUS, et_node, 'definition', stage_data, MSGBUSConfig)

    def handle_io(self, et_node, stage_data):
        return self._process_def(self.cfg.IO, et_node, 'definition', stage_data, IOConfig)

    def handle_msr(self, et_node, stage_data): ## TODO
        return self._process_def(self.cfg.MSR, et_node, 'definition', stage_data, MSRConfig)

    def _handle_bar(self, et_node, stage_data, dest, cfg_obj):
        ret_val = []

        for bar in et_node.iter('bar'):
            bus_attr = _config_convert_data(bar, True)
            if 'name' not in bus_attr or 'device' not in bus_attr:
                self.logger.log_debug(f"Missing 'name' or 'device' in {bus_attr}")
                continue
            bar_name = bus_attr['name']
            dev_name = bus_attr['device']
            self._process_bar(stage_data.vid_str, bar_name, bus_attr, dest, cfg_obj)
            ret_val.extend(self._process_config_complex(stage_data, bar_name, dest[stage_data.vid_str][dev_name][bar_name], dev_name))
            hex_dict = make_dict_hex(bus_attr)
            self.logger.log_debug(f"    + {bus_attr['name']:16}: {hex_dict}")
        return ret_val

    def handle_mmiobar(self, et_node, stage_data):
        return self._handle_bar(et_node, stage_data, self.cfg.MMIO_BARS, MMIOBarConfig)

    def handle_iobar(self, et_node, stage_data):
        return self._handle_bar(et_node, stage_data, self.cfg.IO_BARS, IOBarConfig)



class CoreConfig(BaseConfigParser):
    def get_metadata(self):
        return {'ima': self.handle_ima,
                'registers': self.handle_registers,
                'controls': self.handle_controls,
                'locks': self.handle_locks}

    def get_stage(self):
        return Stage.CORE_SUPPORT

    def _make_reg_name(self, stage_data, reg_name, override=False):
        if hasattr(stage_data, "component_name") and stage_data.component_name is not None and override:
            return '.'.join([stage_data.vid_str, stage_data.component_name, reg_name])
        return '.'.join([stage_data.vid_str, stage_data.dev_name, reg_name])
    
    def _add_entry_simple(self, dest, stage_data, et_node, node_name):
        flat_storage = ['control']
        index_data = ['ima']
        for node in et_node.iter(node_name):
            attrs = _config_convert_data(node)

            # Update storage information
            if node_name in index_data:
                attrs['index'] = self._make_reg_name(stage_data, attrs['index'])
                attrs['data'] = self._make_reg_name(stage_data, attrs['data'])
            else:
                attrs['register'] = self._make_reg_name(stage_data, attrs['register'])

            if 'base_reg' in attrs:
                attrs['base_reg'] = self._make_reg_name(stage_data, attrs['base_reg'])

            # Update storage location with new data
            if node_name in flat_storage:
                dest[attrs['name']] = attrs
            else:
                if stage_data.vid_str not in dest:
                    dest[stage_data.vid_str] = {}
                if stage_data.dev_name not in dest[stage_data.vid_str]:
                    dest[stage_data.vid_str][stage_data.dev_name] = {}
                dest[stage_data.vid_str][stage_data.dev_name][attrs['name']] = attrs
            hex_dict = make_dict_hex(attrs)
            self.logger.log_debug(f"    + {attrs['name']:16}: {hex_dict}")

    def handle_ima(self, et_node, stage_data):
        self._add_entry_simple(self.cfg.IMA_REGISTERS, stage_data, et_node, 'ima')

    def handle_registers(self, et_node, stage_data): # TODO: Refactor this function
        for reg in et_node.iter('register'):
            reg_attr = _config_convert_data(reg)
            reg_name = reg_attr['name']

            # Create register storage location if needed and store data
            if stage_data.vid_str not in self.cfg.REGISTERS:
                self.cfg.REGISTERS[stage_data.vid_str] = {}
            if stage_data.dev_name not in self.cfg.REGISTERS[stage_data.vid_str]:
                self.cfg.REGISTERS[stage_data.vid_str][stage_data.dev_name] = {}

            # Patch missing or incorrect data
            if 'desc' not in reg_attr:
                reg_attr['desc'] = reg_name
            if reg_attr['type'] in ['pcicfg', 'mmcfg', 'mm_msg_bus']:
                reg_attr['device'] = stage_data.dev_name
            elif reg_attr['type'] in ['memory']:
                reg_attr['range'] = stage_data.dev_name
            elif reg_attr['type'] in ['mmio', 'iobar']:
                    reg_attr['bar'] = self._make_reg_name(stage_data, reg_attr['bar'], True)
            if 'size' not in reg_attr:
                self.logger.log_hal(f'Error missing size within {reg_attr}')

            # Get existing field data
            if reg_name in self.cfg.REGISTERS[stage_data.vid_str][stage_data.dev_name]:
                reg_fields = self.cfg.REGISTERS[stage_data.vid_str][stage_data.dev_name][reg_name][0].fields
            else:
                reg_fields = {}

            for field in reg.iter('field'):
                field_attr = _config_convert_data(field)
                field_name = field_attr['name']

                # Locked by attributes need to be handled here due to embedding information in field data
                if 'lockedby' in field_attr:
                    if field_attr['lockedby'].count('.') == 3:
                        lockedby = field_attr['lockedby']
                    elif field_attr['lockedby'].count('.') <= 1:
                        lockedby = self._make_reg_name(stage_data, field_attr['lockedby'])
                    else:
                        self.logger.log_debug(f"[*] Invalid locked by reference: {field_attr['lockedby']}")
                        lockedby = None
                    if lockedby:
                        lreg = self._make_reg_name(stage_data, reg_name, False)
                        if lockedby in self.cfg.LOCKEDBY[stage_data.vid_str]:
                            self.cfg.LOCKEDBY[stage_data.vid_str][lockedby].append({lreg, field_name})
                        else:
                            self.cfg.LOCKEDBY[stage_data.vid_str][lockedby] = [{lreg, field_name}]

                # Handle rest of field data here
                if 'desc' not in field_attr:
                    field_attr['desc'] = field_name
                reg_fields[field_name] = field_attr

            # Store all register data
            reg_attr['FIELDS'] = reg_fields
            reg_attr.update(stage_data.attrs)
            if reg_attr['type'] == 'pcicfg':
                reg_obj = self.create_register_object_pci(PCIRegisters, reg_attr)
            elif reg_attr['type'] == 'mmcfg':
                reg_obj = self.create_register_object_pci(MMCFGRegisters, reg_attr)
            elif reg_attr['type'] == 'mmio':
                self.logger.log('mmio register')
                self.logger.log(reg_attr)
                reg_obj = self.create_register_object_bar(MMIORegisters, reg_attr)
            elif reg_attr['type'] == 'iobar':
                reg_obj = self.create_register_object_bar(IOBARRegisters, reg_attr)
            elif reg_attr['type'] == 'msr':
                threads_to_use = None
                if 'scope' in reg_attr.keys():
                    if reg_attr['scope'] == 'package':
                        packages = self.cfg.CPU['packages']
                        threads_to_use = [packages[p][0] for p in packages]
                    elif reg_attr['scope'] == 'cores':
                        cores = self.cfg.CPU['cores']
                        threads_to_use = [cores[p][0] for p in cores]
                if threads_to_use is None:
                    threads_to_use = range(self.cfg.CPU['threads'])
                reg_obj = self.create_register_object(MSRRegisters, reg_attr, threads_to_use)
            elif reg_attr['type'] == 'io':
                reg_obj = self.create_register_object(IORegisters, reg_attr, [None])
            elif reg_attr['type'] == 'msgbus':
                reg_obj = self.create_register_object(MSGBUSRegisters, reg_attr, [None])
            elif reg_attr['type'] == 'mm_msgbus':
                reg_obj = self.create_register_object(MM_MSGBUSRegisters, reg_attr, [None])
            elif reg_attr['type'] == 'memory':
                reg_obj = self.create_register_object(MEMORYRegisters, reg_attr, [None])
            else:
                self.logger.log("Did not create register object for:")
                self.logger.log(reg_attr)
                continue
            self.cfg.REGISTERS[stage_data.vid_str][stage_data.dev_name][reg_name] = reg_obj
            hex_dict = make_dict_hex(reg_attr)
            self.logger.log_debug(f'    + {reg_name:16}: {hex_dict}')


    def create_register_object(self, objtype, regattr, instance_list):
        reg_obj = []
        for instance in instance_list:
            regattr['instance'] = instance
            reg_obj.append(objtype(regattr))
        return reg_obj

    def create_register_object_bar(self, objtype, regattr):
        reg_obj = []
        for instance in regattr['tmp'].values():
            regattr['instance'] = instance
            reg_obj.append(objtype(regattr))
        return reg_obj

    def create_register_object_pci(self, objtype, regattr):
        reg_obj = []
        for instance in regattr['tmp'].values():
            regattr['instance'] = instance
            reg_obj.append(objtype(regattr, instance))
        return reg_obj if reg_obj else None

    def handle_controls(self, et_node, stage_data):
        for node in et_node.iter('control'):
            attrs = _config_convert_data(node)
            regs = []
            name = attrs['name']
            if attrs['register'] in self.cfg.REGISTERS[stage_data.vid_str][stage_data.dev_name]:
                regs.extend(self.cfg.REGISTERS[stage_data.vid_str][stage_data.dev_name][attrs['register']])
            attrs['register'] = self._make_reg_name(stage_data, attrs['register'])
            objs = []
            for reg in regs:
                cont_obj = CONTROLHelper(attrs, reg)
                objs.append(cont_obj)

            # Update storage location with new data
            self.cfg.CONTROLS[name] = objs
            hex_dict = make_dict_hex(attrs)
            self.logger.log_debug(f"    + {attrs['name']:16}: {hex_dict}")

    def handle_locks(self, et_node, stage_data):
        for node in et_node.iter('lock'):
            attrs = _config_convert_data(node)
            attrs['register'] = self._make_reg_name(stage_data, attrs['register'])
            dest_name = attrs['register']
            if 'field' in attrs:
                dest_name = '.'.join([dest_name, attrs['field']])
            self.cfg.LOCKS[dest_name] = LOCKSHelper(*self.get_lock_data(attrs))
            hex_dict = make_dict_hex(attrs)
            self.logger.log_debug(f"    + {dest_name:16}: {hex_dict}")

    def get_lock_data(self, lock_attr):
        retval = []
        for val in ['register', 'field', 'type', 'value', 'dependency', 'dep_value']:
            if val in lock_attr:
                retval.append(lock_attr[val])
            else:
                retval.append(None)
        return retval
    


parsers = [PlatformInfo, DevConfig, CoreConfig]
