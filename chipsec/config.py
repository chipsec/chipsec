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
#

from collections import namedtuple
from fnmatch import fnmatch
import importlib
import re
import os
import xml.etree.ElementTree as ET
from chipsec.library.defines import is_hex, CHIPSET_CODE_UNKNOWN
from chipsec.library.exceptions import CSConfigError
from chipsec.library.file import get_main_dir
from chipsec.library.logger import logger
from chipsec.library.register import RegList
from chipsec.parsers import Stage
from chipsec.parsers import stage_info, config_data
from chipsec.cfg.parsers.ip.pci_device import PCIConfig


scope_name = namedtuple("scope_name", ["vid", "parent", "name", "fields"])
# Python 3.6 namedtuple does not accept defaults
scope_name.__new__.__defaults__ = (None,) * 4

PROC_FAMILY = {}

class Cfg:
    def __init__(self):
        self.logger = logger()
        self.parent_keys = ["CONFIG_PCI_RAW", "CONFIG_PCI", "MEMORY_RANGES", "MM_MSGBUS", "MSGBUS", "IO", "MSR", "MMIO_BARS", "IO_BARS"]
        self.child_keys = ["IMA_REGISTERS", "REGISTERS", "CONTROLS", "LOCKS", "LOCKEDBY"]
        for key in self.parent_keys + self.child_keys:
            setattr(self, key, {})
        self.XML_CONFIG_LOADED = False

        self.proc_dictionary = {}
        self.proc_codes = set()
        self.pch_dictionary = {}
        self.pch_codes = set()
        self.device_dictionary = {}
        self.device_codes = set()
        self.platform_xml_files = {}
        self.load_list = []
        self.load_extra = []
        self.scope = {None: ''}
        self.parsers = []

        self.detection_dictionary = {}

        # Initialize CPU and PCH artifacts
        self.vid = 0xFFFF
        self.did = 0xFFFF
        self.rid = 0xFF
        self.code = CHIPSET_CODE_UNKNOWN
        self.longname = "Unrecognized Platform"
        self.cpuid = 0xFFFFF
        self.pch_vid = 0xFFFF
        self.pch_did = 0xFFFF
        self.pch_rid = 0xFF
        self.pch_code = CHIPSET_CODE_UNKNOWN
        self.pch_longname = 'Unrecognized PCH'
        self.req_pch = False

    ###
    # Private functions
    ###
    def _get_vid_from_filename(self, fname):
        search_string = re.compile(r'cfg.[0-9a-fA-F]+')
        match = search_string.search(fname)
        vid = match.group(0)[4:]
        return vid

    def _make_hex_key_str(self, int_val):
        str_val = f'{int_val:04X}'
        return str_val
    
    def _create_vid(self, vid_str):
        key_list = self.parent_keys + self.child_keys
        skip_keys = ["LOCKS"]
        if vid_str not in self.CONFIG_PCI:
            for key in key_list:
                if key in skip_keys:
                    continue
                mdict = getattr(self, key)
                mdict[vid_str] = {}

    ###
    # PCI device tree enumeration
    ###
    def set_pci_data(self, enum_devices):
        if not hasattr(self, 'CONFIG_PCI_RAW'):
            setattr(self, 'CONFIG_PCI_RAW', {})
        for b, d, f, vid, did, rid in enum_devices:
            vid_str = self._make_hex_key_str(vid)
            did_str = self._make_hex_key_str(did)
            pci_data = {
                'bus': [b],
                'dev': d,
                'fun': f,
                'vid': vid,
                'did': did,
                'rid': rid}
            if vid_str not in self.CONFIG_PCI_RAW:
                self._create_vid(vid_str)
            if did_str not in self.CONFIG_PCI_RAW[vid_str]:
                pci_obj = PCIConfig(pci_data)
                self.CONFIG_PCI_RAW[vid_str][did_str] = pci_obj
                continue
            self.CONFIG_PCI_RAW[vid_str][did_str].add_obj(pci_data)

    ###
    # CPU topology info
    ###
    def set_topology(self, topology):
        if not hasattr(self, 'CPU'):
            setattr(self, 'CPU', {})
        self.CPU.update(topology)
        self.logger.log_hal(f'Added topology to self.CPU\n{self.CPU}')

    ###
    # Platform detection functions
    ###
    def get_chipset_code(self):
        return self.code

    def get_pch_code(self):
        return self.pch_code

    def is_pch_req(self):
        return self.req_pch

    def print_platform_info(self):
        self.logger.log(f'Platform: {self.longname}')
        self.logger.log(f'\tCPUID: {self.cpuid:X}')
        self.logger.log(f'\tVID: {self.vid:04X}')
        self.logger.log(f'\tDID: {self.did:04X}')
        self.logger.log(f'\tRID: {self.rid:02X}')

    def print_pch_info(self):
        self.logger.log(f'Platform: {self.pch_longname}')
        self.logger.log(f'\tVID: {self.pch_vid:04X}')
        self.logger.log(f'\tDID: {self.pch_did:04X}')
        self.logger.log(f'\tRID: {self.pch_rid:02X}')

    def print_supported_chipsets(self):
        fmtStr = ' {:4} | {:4} | {:14} | {:6} | {:40}'
        self.logger.log('\nSupported platforms:\n')
        self.logger.log(fmtStr.format('VID', 'DID', 'Name', 'Code', 'Long Name'))
        self.logger.log('-' * 85)
        for _vid in sorted(self.proc_dictionary):
            for _did in sorted(self.proc_dictionary[_vid]):
                for item in self.proc_dictionary[_vid][_did]:
                    self.logger.log(fmtStr.format(_vid, _did, item['name'], item['code'].lower(), item['longname'][:40]))

    ###
    # Private config functions
    ###
    def _get_stage_parsers(self, stage):
        handlers = {}
        for parser in self.parsers:
            if parser.get_stage() != stage:
                continue
            if parser.parser_name() in handlers:
                raise CSConfigError(f"Tag handlers already contain handlers for parser {parser.parser_name()}")
            handlers.update({parser.parser_name(): parser.get_metadata()})
        return handlers

    def _update_supported_platforms(self, conf_data, data):
        if not data:
            return
        if data.family and data.proc_code:
            fam = data.family.lower()
            if fam not in PROC_FAMILY:
                PROC_FAMILY[fam] = []
            PROC_FAMILY[fam].append(data.proc_code)
        if data.proc_code:
            dest = self.proc_dictionary
            self.proc_codes.add(data.proc_code)
            if data.proc_code not in self.platform_xml_files:
                self.platform_xml_files[data.proc_code] = []
            self.platform_xml_files[data.proc_code].append(conf_data)
        elif data.pch_code:
            dest = self.pch_dictionary
            self.pch_codes.add(data.pch_code)
            if data.pch_code not in self.platform_xml_files:
                self.platform_xml_files[data.pch_code] = []
            self.platform_xml_files[data.pch_code].append(conf_data)
        else:
            dest = self.device_dictionary
            if 'devices' not in self.platform_xml_files:
                self.platform_xml_files['devices'] = []
            self.platform_xml_files['devices'].append(conf_data)
        if data.vid_str not in dest:
            dest[data.vid_str] = {}
        for sku in data.sku_list:
            did_list = [sku['did']] if type(sku['did']) is int else sku['did']
            for did in did_list:
                did_str = self._make_hex_key_str(did)
                if did_str not in dest[data.vid_str]:
                    dest[data.vid_str][did_str] = []
                sku['req_pch'] = data.req_pch
                sku['detect'] = data.detect_vals
                dest[data.vid_str][did_str].append(sku)

    def _find_possible_skus_from_detection_value(self, dict_ref, detect_val):
        possible_skus = {}
        if detect_val:
            for vid in self.vid_set:
                for did in dict_ref[vid]:
                    for sku in dict_ref[vid][did]:
                        if 'detect' in sku:
                            if detect_val in sku['detect']:
                                if vid not in possible_skus:
                                    possible_skus[vid] = {}
                                if did not in possible_skus[vid]:
                                    possible_skus[vid][did] = []
                                possible_skus[vid][did].append(sku)
        else:
            possible_skus = dict_ref
        return possible_skus

    def _find_sku_from_code(self, dict_ref, code):
        if code:
            for vid in self.vid_set:
                for did in dict_ref[vid]:
                    for sku in dict_ref[vid][did]:
                        if code.upper() == sku['code']:
                            return sku
        return None

    def _find_sku_from_pci_raw(self, dict_ref):
        for vid in self.vid_set:
            try:
                did_set = set(dict_ref[vid].keys()).intersection(set(self.CONFIG_PCI_RAW[vid].keys()))
            except KeyError:
                did_set = []
            for did in did_set:
                for sku in dict_ref[vid][did]:
                    return sku
        return None

    def create_unknown_sku(self):
        dev000 = self.get_dev_from_bdf_000()
        return {'did': [dev000['did']], 'name': 'Unknown', 'code': 'UNKN', 'longname': 'Unknown Platform', 'vid': dev000['vid'], 'req_pch': None, 'detect': []}

    def _find_sku_data(self, dict_ref, code, detect_val=None):
        try:
            self.vid_set = set(dict_ref.keys()).intersection(set(self.CONFIG_PCI_RAW.keys()))
        except KeyError:
            return self.create_unknown_sku()

        possible_skus = self._find_possible_skus_from_detection_value(dict_ref, detect_val)
        sku = self._find_sku_from_code(dict_ref, code)
        if sku:
            return sku

        sku = self._find_sku_from_pci_raw(possible_skus)
        if sku:
            return sku

        # Find SKU based on DID only
        sku = self._find_sku_from_pci_raw(dict_ref)
        if sku:
            return sku

        if possible_skus and detect_val:
            if len(possible_skus) > 1:
                self.logger.log_warning('Multiple SKUs found for detection value, using first in the list')
            sku = possible_skus.popitem()[1].popitem()[1].pop()
            sku['longname'] = f"{sku['code']} Generic"
            return sku
        return None

    def _find_did(self, sku):
        vid_str = self._make_hex_key_str(sku['vid'])
        if 'did' in sku and type(sku['did']) is int:
            return sku['did']
        else:
            for did in sku['did']:
                did_str = self._make_hex_key_str(did)
                if vid_str in self.CONFIG_PCI_RAW and did_str in self.CONFIG_PCI_RAW[vid_str]:
                    return did
        self.logger.log_warning('Enumerated Platform PCI DID not found in XML Configs. System info may not be 100% accurate.')
        return 0xFFFF

    def _get_config_iter(self, fxml):
        tree = ET.parse(fxml.xml_file)
        root = tree.getroot()
        return root.iter('configuration')
    
    def _get_sec_parser_name(self, root, stage):
        if 'custom_parser' in root.attrib:
            return root.attrib['custom_parser']
        for parser in self.parsers:
            if parser.get_stage() == stage:
                return parser.parser_name()

    def _load_sec_configs(self, load_list, stage):
        stage_str = 'core' if stage == Stage.CORE_SUPPORT else 'custom'
        cfg_handlers = self._get_stage_parsers(stage)
        if not load_list or not cfg_handlers:
            return
        for fxml in load_list:
            self.logger.log_debug(f'[*] Loading {stage_str} config data: [{fxml.dev_name}] - {fxml.xml_file}')
            if not os.path.isfile(fxml.xml_file):
                self.logger.log_debug(f'[-] File not found: {fxml.xml_file}')
                continue
            for config_root in self._get_config_iter(fxml):
                parser_name = self._get_sec_parser_name(config_root, stage)
                tag_handlers = cfg_handlers[parser_name] if parser_name in cfg_handlers else []
                for tag in tag_handlers:
                    self.logger.log_debug(f'[*] Loading {tag} data...')
                    for node in config_root.iter(tag):
                        tag_handlers[tag](node, fxml)

    ###
    # Config loading functions
    ###
    def load_parsers(self):
        parser_path = os.path.join(get_main_dir(), 'chipsec', 'cfg', 'parsers')
        if not os.path.isdir(parser_path):
            raise CSConfigError(f'Unable to locate configuration parsers: {parser_path}')
        parser_files = [f for f in sorted(os.listdir(parser_path))
                        if fnmatch(f, '*.py') and not fnmatch(f, '__init__.py')]
        for parser in parser_files:
            parser_name = '.'.join(['chipsec', 'cfg', 'parsers', os.path.splitext(parser)[0]])
            self.logger.log_debug(f'[*] Importing parser: {parser_name}')
            try:
                module = importlib.import_module(parser_name)
            except Exception as err:
                self.logger.log_debug(f'[*] Failed to import {parser_name}')
                self.logger.log_debug(err)
                continue
            if not hasattr(module, 'parsers'):
                self.logger.log_debug(f'[*] Missing parsers variable: {parser}')
                continue
            for obj in module.parsers:
                try:
                    parser_obj = obj(self)
                except Exception:
                    self.logger.log_debug(f'[*] Failed to create object: {parser}')
                    continue
                parser_obj.startup()
                self.parsers.append(parser_obj)

    def add_extra_configs(self, path, filename=None, loadnow=False):
        config_path = os.path.join(get_main_dir(), 'chipsec', 'cfg', path)
        if os.path.isdir(config_path) and filename is None:
            self.load_extra = [config_data(None, None, os.path.join(config_path, f)) for f in sorted(os.listdir(config_path))
                               if fnmatch(f, '*.xml')]
        elif os.path.isdir(config_path) and filename:
            self.load_extra = [config_data(None, None, os.path.join(config_path, f)) for f in sorted(os.listdir(config_path))
                               if fnmatch(f, '*.xml') and fnmatch(f, filename)]
        else:
            raise CSConfigError(f'Unable to locate configuration file(s): {config_path}')
        if loadnow and self.load_extra:
            self._load_sec_configs(self.load_extra, Stage.EXTRA)

    def load_platform_info(self):
        info_handlers = self._get_stage_parsers(Stage.GET_INFO)
        tag_handlers = info_handlers['PlatformInfo']
        cfg_path = os.path.join(get_main_dir(), 'chipsec', 'cfg')

        # Locate all root configuration files
        cfg_files = []
        cfg_vids = [f.name for f in os.scandir(cfg_path) if f.is_dir() and is_hex(f.name)]
        for vid_str in cfg_vids:
            root_path = os.path.join(cfg_path, vid_str)
            cfg_files.extend([config_data(vid_str, None, f.path, None, None)
                             for f in sorted(os.scandir(root_path), key=lambda x: x.name)
                             if fnmatch(f.name, '*.xml')])

        # Process platform info data and generate lookup tables
        for fxml in cfg_files:
            self.logger.log_debug(f'[*] Processing platform config information: {fxml.xml_file}')
            for config_root in self._get_config_iter(fxml):
                stage_data = stage_info(fxml.vid_str, config_root)
                for tag in tag_handlers:
                    for node in config_root.iter(tag):
                        data = tag_handlers[tag](node, stage_data)
                        if not data:
                            continue
                        self._update_supported_platforms(fxml, data)

        # Create platform global data
        for cc in self.proc_codes:
            globals()[f'CHIPSET_CODE_{cc.upper()}'] = cc.upper()
        for pc in self.pch_codes:
            globals()[f'PCH_CODE_{pc[4:].upper()}'] = pc.upper()

    def get_dev_from_bdf_000(self):
        for vid in self.CONFIG_PCI_RAW:
            for did in self.CONFIG_PCI_RAW[vid]:
                if 0 in self.CONFIG_PCI_RAW[vid][did]['bus'] and self.CONFIG_PCI_RAW[vid][did]['dev'] == 0 and self.CONFIG_PCI_RAW[vid][did]['fun'] == 0:
                    return self.CONFIG_PCI_RAW[vid][did]
        return {'vid': 0xFFFF, 'did': 0xFFFF, 'rid': 0xFF}

    def platform_detection(self, proc_code, pch_code, cpuid):
        # Detect processor files
        self.cpuid = cpuid
        sku = self._find_sku_data(self.proc_dictionary, proc_code, cpuid)
        if sku:
            self.vid = sku['vid']
            self.did = self._find_did(sku)
            if self.did == 0xFFFF:
                self.did = self.get_dev_from_bdf_000()['did']
            self.code = sku['code']
            if not proc_code:
                vid_str = self._make_hex_key_str(self.vid)
                did_str = self._make_hex_key_str(self.did)
                self.rid = self.CONFIG_PCI_RAW[vid_str][did_str].get_rid(0, 0, 0)
            else:
                raise CSConfigError("There is already a CPU detected, are you adding a new config?")
            self.longname = sku['longname']
            self.req_pch = sku['req_pch']
        else:
            dev000 = self.get_dev_from_bdf_000()
            self.vid = dev000['vid']
            self.did = dev000['did']
            self.rid = dev000['rid']

        # Detect PCH files
        sku = self._find_sku_data(self.pch_dictionary, pch_code)
        if sku:
            self.pch_vid = sku['vid']
            self.pch_did = self._find_did(sku)
            self.pch_code = sku['code']
            if not pch_code:
                vid_str = self._make_hex_key_str(self.pch_vid)
                did_str = self._make_hex_key_str(self.pch_did)
                for cfg_data in self.CONFIG_PCI_RAW[vid_str][did_str]:
                    if 0x31 == cfg_data['dev'] and 0x0 == cfg_data['fun']:
                        self.rid = cfg_data['rid']
            else:
                raise CSConfigError("There is already a PCH detected, are you adding a new config?")
            self.pch_longname = sku['longname']

        # Create XML file load list
        if self.code:
            self.load_list.extend(self.platform_xml_files[self.code])
        if self.pch_code:
            self.load_list.extend(self.platform_xml_files[self.pch_code])
        if 'devices' in self.platform_xml_files:
            self.load_list.extend(self.platform_xml_files['devices'])

    def load_platform_config(self):
        sec_load_list = []
        cfg_handlers = self._get_stage_parsers(Stage.DEVICE_CFG)
        tag_handlers = cfg_handlers['DevConfig']
        for fxml in self.load_list:
            self.logger.log_debug(f'[*] Loading primary config data: {fxml.xml_file}')
            for config_root in self._get_config_iter(fxml):
                for tag in tag_handlers:
                    self.logger.log_debug(f'[*] Collecting {tag} configuration data...')
                    for node in config_root.iter(tag):
                        sec_load_list.extend(tag_handlers[tag](node, fxml))
        self._load_sec_configs(sec_load_list, Stage.CORE_SUPPORT)
        self._load_sec_configs(sec_load_list, Stage.CUST_SUPPORT)
        if self.load_extra:
            self._load_sec_configs(self.load_extra, Stage.EXTRA)


    ###
    # Scoping Functions
    ###
    def set_scope(self, scope):
        self.scope.update(scope)

    def get_scope(self, name):
        if '.' in name:
            return ''
        elif name in self.scope:
            return self.scope[name]
        else:
            return self.scope[None]

    def clear_scope(self):
        self.scope = {None: ''}

    def convert_internal_scope(self, scope, name):
        if scope:
            sname = scope + '.' + name
        else:
            sname = name
        return scope_name(*(sname.split('.', 3)))


    ###
    # Control Functions
    ###

    def get_control_def(self, control_name):
        return self.CONTROLS[control_name]

    def is_control_defined(self, control_name):
        return True if control_name in self.CONTROLS else False

    def get_control_obj(self, control_name, instance=None):
        controls = RegList()
        if control_name in self.CONTROLS.keys():
            if instance is not None and 'obj' in self.CONTROLS[control_name].keys():
                return self.CONTROLS[control_name]['obj'][instance]
            controls.extend(self.CONTROLS[control_name]['obj'])
        return controls
    

    ###
    # Register Functions
    ###
    def get_register_def(self, reg_name):
        scope = self.get_scope(reg_name)
        vid, dev_name, register, _ = self.convert_internal_scope(scope, reg_name)
        reg_def = self.REGISTERS[vid][dev_name][register]
        if reg_def["type"] in ["pcicfg", "mmcfg"]:
            dev = self.CONFIG_PCI[vid][dev_name]
            reg_def['bus'] = dev['bus']
            reg_def['dev'] = dev['dev']
            reg_def['fun'] = dev['fun']
        elif reg_def["type"] == "memory":
            dev = self.MEMORY_RANGES[vid][dev_name]
            reg_def['address'] = dev['address']
            reg_def['access'] = dev['access']
        elif reg_def["type"] == "mm_msgbus":
            dev = self.MM_MSGBUS[vid][dev_name]
            reg_def['port'] = dev['port']
        elif reg_def["type"] == "indirect":
            dev = self.IMA_REGISTERS[vid][dev_name]
            if ('base' in dev):
                reg_def['base'] = dev['base']
            else:
                reg_def['base'] = "0"
            if (dev['index'] in self.REGISTERS[vid][dev_name]):
                reg_def['index'] = dev['index']
            else:
                logger().log_error("Index register {} not found".format(dev['index']))
            if (dev['data'] in self.REGISTERS[vid][dev_name]):
                reg_def['data'] = dev['data']
            else:
                logger().log_error("Data register {} not found".format(dev['data']))
        return reg_def

    def get_register_obj(self, reg_name, instance=None):
        reg_def = RegList()
        scope = self.get_scope(reg_name)
        vid, dev_name, register, _ = self.convert_internal_scope(scope, reg_name)
        if vid in self.REGISTERS and dev_name in self.REGISTERS[vid] and register in self.REGISTERS[vid][dev_name]:
            reg_def.extend(self.REGISTERS[vid][dev_name][register]['obj'])
        for reg_obj in reg_def:
            if reg_obj.instance == instance:
                return reg_obj
        if instance is not None:
            return RegList()
        else:
            return reg_def

    def get_mmio_def(self, bar_name):
        ret = None
        scope = self.get_scope(bar_name)
        vid, device, bar, _ = self.convert_internal_scope(scope, bar_name)
        if vid in self.MMIO_BARS and device in self.MMIO_BARS[vid]:
            if bar in self.MMIO_BARS[vid][device]:
                ret = self.MMIO_BARS[vid][device][bar]
        return ret




    def get_device_bus(self, dev_name):
        scope = self.get_scope(dev_name)
        vid, device, _, _ = self.convert_internal_scope(scope, dev_name)
        if vid in self.CONFIG_PCI and device in self.CONFIG_PCI[vid]:
            return self.CONFIG_PCI[vid][device]["bus"]
        else:
            return None

    def is_register_defined(self, reg_name):
        scope = self.get_scope(reg_name)
        vid, device, register, _ = self.convert_internal_scope(scope, reg_name)
        try:
            return (self.REGISTERS[vid][device].get(register, None) is not None)
        except KeyError:
            return False

    def is_device_defined(self, dev_name):
        scope = self.get_scope(dev_name)
        vid, device, _, _ = self.convert_internal_scope(scope, dev_name)
        if self.CONFIG_PCI[vid].get(device, None) is None:
            return False
        else:
            return True

    def get_device_BDF(self, device_name):
        scope = self.get_scope(device_name)
        vid, device, _, _ = self.convert_internal_scope(scope, device_name)
        try:
            device = self.CONFIG_PCI[vid][device]
        except KeyError:
            device = None
        if device is None or device == {}:
            raise DeviceNotFoundError('DeviceNotFound: {}'.format(device_name))
        b = device['bus']
        d = device['dev']
        f = device['fun']
        return (b, d, f)

    def register_has_field(self, reg_name, field_name):
        scope = self.get_scope(reg_name)
        vid, device, register, _ = self.convert_internal_scope(scope, reg_name)
        try:
            reg_def = self.REGISTERS[vid][device][register]
        except KeyError:
            return False
        if 'FIELDS' not in reg_def:
            return False
        return (field_name in reg_def['FIELDS'])

    def get_REGISTERS_match(self, name):
        vid, device, register, field = self.convert_internal_scope("", name)
        ret = []
        if vid is None or vid == '*':
            vid = self.REGISTERS.keys()
        else:
            vid = [vid]
        for v in vid:
            if v in self.REGISTERS:
                if device is None or device == "*":
                    dev = self.REGISTERS[v].keys()
                else:
                    dev = [device]
                for d in dev:
                    if d in self.REGISTERS[v]:
                        if register is None or register == "*":
                            reg = self.REGISTERS[v][d].keys()
                        else:
                            reg = [register]
                        for r in reg:
                            if r in self.REGISTERS[v][d]:
                                if field is None or field == "*":
                                    fld = self.REGISTERS[v][d][r]['FIELDS'].keys()
                                else:
                                    if field in self.REGISTERS[v][d][r]['FIELDS']:
                                        fld = [field]
                                    else:
                                        fld = []
                                for f in fld:
                                    ret.append("{}.{}.{}.{}".format(v, d, r, f))
        return ret

    def get_MMIO_match(self, name):
        vid, device, inbar, _ = self.convert_internal_scope("", name)
        ret = []
        if vid is None or vid == '*':
            vid = self.REGISTERS.keys()
        else:
            vid = [vid]
        for v in vid:
            if v in self.MMIO_BARS:
                if device is None or device == '*':
                    dev = self.MMIO_BARS[v].keys()
                else:
                    dev = [device]
                for d in dev:
                    if d in self.MMIO_BARS[v]:
                        if inbar is None or inbar == '*':
                            bar = self.MMIO_BARS[v][d]
                        else:
                            bar = [inbar]
                        for b in bar:
                            if b in self.MMIO_BARS[v][d]:
                                ret.append("{}.{}.{}".format(v, d, b))
        return ret

    ###
    # Locks functions
    ###
    def get_lock_list(self):
        return self.LOCKS.keys()

    def is_lock_defined(self, lock_name):
        return lock_name in self.LOCKS.keys()

    def get_locked_value(self, lock_name):
        logger().log_debug('Retrieve value for lock {}'.format(lock_name))
        return self.LOCKS[lock_name]['value']

    def get_lock_desc(self, lock_name):
        return self.LOCKS[lock_name]['desc']

    def get_lock_type(self, lock_name):
        if 'type' in self.LOCKS[lock_name]:
            mtype = self.LOCKS[lock_name]['type']
        else:
            mtype = "RW/L"
        return mtype

    def get_lockedby(self, lock_name):
        vid, _, _, _ = self.convert_internal_scope("", lock_name)
        if lock_name in self.LOCKEDBY[vid]:
            return self.LOCKEDBY[vid][lock_name]
        else:
            return None