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

from fnmatch import fnmatch
import importlib
import os
import xml.etree.ElementTree as ET
from chipsec.library.defines import is_hex
from chipsec.library.exceptions import CSConfigError
from chipsec.library.file import get_main_dir
from chipsec.library.logger import logger
from chipsec.parsers import Stage
from chipsec.parsers import stage_info, config_data

LOAD_COMMON = True

CHIPSET_ID_UNKNOWN = 0

CHIPSET_CODE_UNKNOWN = ''

PROC_FAMILY = {}

PCH_CODE_PREFIX = 'PCH_'


class Cfg:
    def __init__(self):
        self.logger = logger()
        self.CONFIG_PCI = {}
        self.REGISTERS = {}
        self.MMIO_BARS = {}
        self.IO_BARS = {}
        self.IMA_REGISTERS = {}
        self.MEMORY_RANGES = {}
        self.CONTROLS = {}
        self.BUS = {}
        self.LOCKS = {}
        self.LOCKEDBY = {}
        self.XML_CONFIG_LOADED = False

        self.proc_dictionary = {}
        self.proc_codes = set()
        self.pch_dictionary = {}
        self.pch_codes = set()
        self.device_dictionary = {}
        self.platform_xml_files = {}
        self.load_list = []
        self.load_extra = []
        self.parsers = []
        self.cpuid = 0xFFFFF

        self.detection_dictionary = {}

        # Initialize CPU and PCH artifacts
        self.vid = 0xFFFF
        self.did = 0xFFFF
        self.rid = 0xFF
        self.code = CHIPSET_CODE_UNKNOWN
        self.longname = "Unrecognized Platform"
        self.pch_vid = 0xFFFF
        self.pch_did = 0xFFFF
        self.pch_rid = 0xFF
        self.pch_code = CHIPSET_CODE_UNKNOWN
        self.pch_longname = 'Unrecognized PCH'
        self.req_pch = False

    ###
    # Private functions
    ###
    def _make_hex_key_str(self, int_val):
        str_val = '{:04X}'.format(int_val)
        return str_val

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
                self.CONFIG_PCI_RAW[vid_str] = {}
            if did_str not in self.CONFIG_PCI_RAW[vid_str]:
                self.CONFIG_PCI_RAW[vid_str][did_str] = pci_data
            elif b not in self.CONFIG_PCI_RAW[vid_str][did_str]['bus']:
                self.CONFIG_PCI_RAW[vid_str][did_str]['bus'].append(b)

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
        self.logger.log(f"Platform: {self.longname}")
        self.logger.log(f'\tCPUID: {self.cpuid:X}')
        self.logger.log(f"\tVID: {self.vid:04X}")
        self.logger.log(f"\tDID: {self.did:04X}")
        self.logger.log(f"\tRID: {self.rid:02X}")
        
    def print_pch_info(self):
        self.logger.log(f"Platform: {self.pch_longname}")
        self.logger.log(f"\tVID: {self.pch_vid:04X}")
        self.logger.log(f"\tDID: {self.pch_did:04X}")
        self.logger.log(f"\tRID: {self.pch_rid:02X}")

    def print_supported_chipsets(self):
        fmtStr = " {:4} | {:4} | {:14} | {:6} | {:40}"
        self.logger.log("\nSupported platforms:\n")
        self.logger.log(fmtStr.format("VID", "DID", "Name", "Code", "Long Name"))
        self.logger.log("-" * 85)
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
            handlers.update(parser.get_metadata())
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
            for did in sku['did']:
                did_str = self._make_hex_key_str(did)
                if did_str not in dest[data.vid_str]:
                    dest[data.vid_str][did_str] = []
                sku['req_pch'] = data.req_pch
                sku['detect'] = data.detect_vals
                dest[data.vid_str][did_str].append(sku)

    def _find_sku_data(self, dict_ref, code, detect_val=None):
        possible_sku = []
        for vid_str in dict_ref:
            for did_str in dict_ref[vid_str]:
                for sku in dict_ref[vid_str][did_str]:
                    if code and sku['code'] != code.upper():
                        continue
                    if not code:
                        if vid_str not in self.CONFIG_PCI_RAW:
                            continue
                        if did_str not in self.CONFIG_PCI_RAW[vid_str]:
                            continue
                        if sku['detect'] and detect_val and detect_val not in sku['detect']:
                            possible_sku.append(sku)
                            continue
                    return sku
        if possible_sku:
            if len(possible_sku) > 1:
                logger().log_warning("Multiple SKUs found for detection value")
            return possible_sku.pop()
        return None
    
    def _find_did(self, sku):
        vid_str = self._make_hex_key_str(sku['vid'])
        if 'did' in sku and sku['did'] is int:
            return sku['did']
        else:
            for did in sku['did']:
                did_str = self._make_hex_key_str(did)
                if did_str in self.CONFIG_PCI_RAW[vid_str]:
                    return did
        return 0xFFFF

    def _get_config_iter(self, fxml):
        tree = ET.parse(fxml.xml_file)
        root = tree.getroot()
        return root.iter('configuration')

    def _load_sec_configs(self, load_list, stage):
        stage_str = 'core' if stage == Stage.CORE_SUPPORT else 'custom'
        tag_handlers = self._get_stage_parsers(stage)
        if not load_list or not tag_handlers:
            return
        for fxml in load_list:
            self.logger.log_debug('[*] Loading {} config data: [{}] - {}'.format(stage_str,
                                                                                 fxml.dev_name,
                                                                                 fxml.xml_file))
            if not os.path.isfile(fxml.xml_file):
                self.logger.log_debug('[-] File not found: {}'.format(fxml.xml_file))
                continue
            for config_root in self._get_config_iter(fxml):
                for tag in tag_handlers:
                    self.logger.log_debug('[*] Loading {} data...'.format(tag))
                    for node in config_root.iter(tag):
                        tag_handlers[tag](node, fxml)

    ###
    # Config loading functions
    ###
    def load_parsers(self):
        parser_path = os.path.join(get_main_dir(), 'chipsec', 'cfg', 'parsers')
        if not os.path.isdir(parser_path):
            raise CSConfigError('Unable to locate configuration parsers: {}'.format(parser_path))
        parser_files = [f for f in sorted(os.listdir(parser_path))
                        if fnmatch(f, '*.py') and not fnmatch(f, '__init__.py')]
        for parser in parser_files:
            parser_name = '.'.join(['chipsec', 'cfg', 'parsers', os.path.splitext(parser)[0]])
            self.logger.log_debug('[*] Importing parser: {}'.format(parser_name))
            try:
                module = importlib.import_module(parser_name)
            except Exception:
                self.logger.log_debug('[*] Failed to import {}'.format(parser_name))
                continue
            if not hasattr(module, 'parsers'):
                self.logger.log_debug('[*] Missing parsers variable: {}'.format(parser))
                continue
            for obj in module.parsers:
                try:
                    parser_obj = obj(self)
                except Exception:
                    self.logger.log_debug('[*] Failed to create object: {}'.format(parser))
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
            raise CSConfigError('Unable to locate configuration file(s): {}'.format(config_path))
        if loadnow and self.load_extra:
            self._load_sec_configs(self.load_extra, Stage.EXTRA)

    def load_platform_info(self):
        tag_handlers = self._get_stage_parsers(Stage.GET_INFO)
        cfg_path = os.path.join(get_main_dir(), 'chipsec', 'cfg')

        # Locate all root configuration files
        cfg_files = []
        cfg_vids = [f for f in os.listdir(cfg_path) if os.path.isdir(os.path.join(cfg_path, f)) and is_hex(f)]
        for vid_str in cfg_vids:
            root_path = os.path.join(cfg_path, vid_str)
            cfg_files.extend([config_data(vid_str, None, os.path.join(root_path, f))
                             for f in sorted(os.listdir(root_path))
                             if fnmatch(f, '*.xml')])

        # Process platform info data and generate lookup tables
        for fxml in cfg_files:
            self.logger.log_debug('[*] Processing platform config information: {}'.format(fxml.xml_file))
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
            globals()["CHIPSET_CODE_{}".format(cc.upper())] = cc.upper()
        for pc in self.pch_codes:
            globals()["PCH_CODE_{}".format(pc[4:].upper())] = pc.upper()

    def platform_detection(self, proc_code, pch_code, cpuid):
        # Detect processor files
        self.cpuid = cpuid
        sku = self._find_sku_data(self.proc_dictionary, proc_code, cpuid)
        if sku:
            self.vid = sku['vid']
            self.did = self._find_did(sku)
            self.code = sku['code']
            if not proc_code:
                vid_str = self._make_hex_key_str(self.vid)
                did_str = self._make_hex_key_str(self.did)
                self.rid = self.CONFIG_PCI_RAW[vid_str][did_str]['rid']
            self.longname = sku['longname']
            self.req_pch = sku['req_pch']

        # Detect PCH files
        sku = self._find_sku_data(self.pch_dictionary, pch_code)
        if sku:
            self.pch_vid = sku['vid']
            self.pch_did = self._find_did(sku)
            self.pch_code = sku['code']
            if not pch_code:
                vid_str = self._make_hex_key_str(self.pch_vid)
                did_str = self._make_hex_key_str(self.pch_did)
                self.pch_rid = self.CONFIG_PCI_RAW[vid_str][did_str]['rid']
            self.pch_longname = sku['longname']

        # Create XML file load list
        if LOAD_COMMON:
            self.load_list.extend(self.get_common_xml())
        if self.code:
            self.load_list.extend(self.platform_xml_files[self.code])
        if self.pch_code:
            self.load_list.extend(self.platform_xml_files[self.pch_code])
        if 'devices' in self.platform_xml_files:
            self.load_list.extend(self.platform_xml_files['devices'])

    def load_platform_config(self):
        sec_load_list = []
        tag_handlers = self._get_stage_parsers(Stage.DEVICE_CFG)
        for fxml in self.load_list:
            self.logger.log_debug('[*] Loading primary config data: {}'.format(fxml.xml_file))
            for config_root in self._get_config_iter(fxml):
                for tag in tag_handlers:
                    self.logger.log_debug('[*] Collecting {} configuration data...'.format(tag))
                    for node in config_root.iter(tag):
                        sec_load_list.extend(tag_handlers[tag](node, fxml))
        self._load_sec_configs(sec_load_list, Stage.CORE_SUPPORT)
        self._load_sec_configs(sec_load_list, Stage.CUST_SUPPORT)
        if self.load_extra:
            self._load_sec_configs(self.load_extra, Stage.EXTRA)

    def get_common_xml(self):
        cfg_path = os.path.join(get_main_dir(), 'chipsec', 'cfg')
        vid = f'{self.vid:X}'

        # Locate all common configuration files
        cfg_files = []
        cfg_vids = [f for f in os.listdir(cfg_path) if os.path.isdir(os.path.join(cfg_path, f)) and is_hex(f)]
        if vid in cfg_vids:
            root_path = os.path.join(cfg_path, vid)
            cfg_files.extend([config_data(vid, None, os.path.join(root_path, f))
                             for f in sorted(os.listdir(root_path))
                             if fnmatch(f, '*.xml') and fnmatch(f, 'common*')])
        return cfg_files
