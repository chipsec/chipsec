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
from chipsec.library.defines import is_hex, CHIPSET_CODE_UNKNOWN
from chipsec.library.exceptions import CSConfigError
from chipsec.library.file import get_main_dir
from chipsec.library.logger import logger
from chipsec.parsers import Stage
from chipsec.parsers import stage_info, config_data

LOAD_COMMON = True

PROC_FAMILY = {}

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
        self.longname = 'Unrecognized Platform'
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
        str_val = f'{int_val:04X}'
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
        if 'did' in sku and sku['did'] is int:
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

    def _load_sec_configs(self, load_list, stage):
        stage_str = 'core' if stage == Stage.CORE_SUPPORT else 'custom'
        tag_handlers = self._get_stage_parsers(stage)
        if not load_list or not tag_handlers:
            return
        for fxml in load_list:
            self.logger.log_debug(f'[*] Loading {stage_str} config data: [{fxml.dev_name}] - {fxml.xml_file}')
            if not os.path.isfile(fxml.xml_file):
                self.logger.log_debug(f'[-] File not found: {fxml.xml_file}')
                continue
            for config_root in self._get_config_iter(fxml):
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
            except Exception:
                self.logger.log_debug(f'[*] Failed to import {parser_name}')
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
                try:
                    self.rid = self.CONFIG_PCI_RAW[vid_str][did_str]['rid']
                except Exception:
                    self.rid = 0xFF
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
