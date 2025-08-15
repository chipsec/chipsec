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
from collections.abc import Iterable
from dataclasses import dataclass, field
from fnmatch import fnmatch
import importlib
import re
import os
from typing import Dict, List, Set, Any, Optional
import xml.etree.ElementTree as ET
from chipsec.library.defines import is_hex, CHIPSET_CODE_UNKNOWN
from chipsec.library.exceptions import (
    CSConfigError, PlatformDetectionError, ConfigurationValidationError, ParserLoadError
)
from chipsec.library.file import get_main_dir
from chipsec.library.logger import logger
from chipsec.library.register import ObjList
from chipsec.library.strings import make_hex_key_str
from chipsec.parsers import Stage
from chipsec.parsers import stage_info, config_data
from chipsec.cfg.parsers.ip.platform import Platform, Vendor
from chipsec.cfg.parsers.ip.pci_device import PCIConfig


@dataclass
class PlatformInfo:
    """Data class for platform information."""
    vid: int = 0xFFFF
    did: int = 0xFFFF
    rid: int = 0xFF
    code: str = CHIPSET_CODE_UNKNOWN
    longname: str = 'Unrecognized Platform'
    name: str = 'Unknown'
    req_pch: Any = None
    detect: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Validate platform info after initialization."""
        if not isinstance(self.detect, list):
            self.detect = []


@dataclass
class PCHInfo:
    """Data class for PCH information."""
    vid: int = 0xFFFF
    did: int = 0xFFFF
    rid: int = 0xFF
    code: str = CHIPSET_CODE_UNKNOWN
    longname: str = 'Unrecognized PCH'


@dataclass
class CPUInfo:
    """Data class for CPU information."""
    cpuid: int = 0xFFFFF
    mfgid: str = 'Unknown CPU'


@dataclass
class ConfigurationState:
    """Data class for configuration state."""
    xml_config_loaded: bool = False
    parsers_loaded: bool = False
    platform_detected: bool = False
    validation_passed: bool = False



class PlatformDetector:
    """Handles platform detection and SKU matching."""

    def __init__(self, logger):
        self.logger = logger
        self.vid_set: Set[str] = set()
        self.config_pci_raw: Dict[str, Any] = {}

    def detect_platform(self, pci_enum: Dict[str, Any],
                        config_pci_raw: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect the platform based on PCI enumeration.

        Args:
            pci_enum: PCI enumeration data
            config_pci_raw: Raw PCI configuration data

        Returns:
            Platform information dictionary

        Raises:
            PlatformDetectionError: If platform detection fails
        """
        self.config_pci_raw = config_pci_raw
        try:
            dev000 = pci_enum['0000:00:00.0']
            dict_ref = config_pci_raw

            # Check if any vendor IDs match
            if not self._check_vendor_compatibility(dict_ref, config_pci_raw):
                return self._get_unknown_platform(dev000)

            # Find matching SKUs
            detect_val = self._get_detection_value(dev000)
            possible_skus = self._find_possible_skus_from_detection_value(
                dict_ref, detect_val
            )

            if not possible_skus:
                self.logger.log_warning(
                    'Enumerated Platform PCI DID not found in XML Configs. '
                    'System info may not be 100% accurate.'
                )
                return self._get_unknown_platform(dev000)

            if len(possible_skus) > 1:
                self.logger.log_warning(
                    'Multiple SKUs found for detection value, '
                    'using first in the list'
                )

            return possible_skus[0]

        except KeyError as e:
            raise PlatformDetectionError(f"Missing required key: {e}")
        except Exception as e:
            raise PlatformDetectionError(f"Platform detection failed: {e}")

    def _check_vendor_compatibility(self, dict_ref: Dict[str, Any],
                                    config_pci_raw: Dict[str, Any]) -> bool:
        """Check if vendor IDs are compatible."""
        self.vid_set = set(dict_ref.keys()).intersection(
            set(config_pci_raw.keys())
        )
        return len(self.vid_set) > 0

    def _get_detection_value(self, dev000: Dict[str, Any]) -> str:
        """Get the detection value from device info."""
        return f"{dev000['vid']:04x}:{dev000['did']:04x}"

    def _get_unknown_platform(self, dev000: Dict[str, Any]) -> Dict[str, Any]:
        """Return unknown platform info."""
        return {
            'did': [dev000['did']],
            'name': 'Unknown',
            'code': 'UNKN',
            'longname': 'Unknown Platform',
            'vid': dev000['vid'],
            'req_pch': None,
            'detect': []
        }

    def _find_possible_skus_from_detection_value(
            self, dict_ref: Dict[str, Any], detect_val: str
    ) -> List[Dict[str, Any]]:
        """Find possible SKUs based on detection value."""
        possible_skus = []

        for vid_str in self.vid_set:
            for did_str in dict_ref[vid_str]:
                if (vid_str in self.config_pci_raw and
                        did_str in self.config_pci_raw[vid_str]):
                    # Check detection patterns
                    sku_info = dict_ref[vid_str][did_str]
                    if self._matches_detection_pattern(sku_info, detect_val):
                        possible_skus.append(sku_info)

        return possible_skus

    def _matches_detection_pattern(self, sku_info: Dict[str, Any],
                                   detect_val: str) -> bool:
        """Check if SKU matches detection pattern."""
        if 'detect' not in sku_info:
            return False

        for pattern in sku_info['detect']:
            if fnmatch(detect_val, pattern):
                return True

        return False


class ConfigurationValidator:
    """Handles configuration validation and schema checking."""

    def __init__(self, logger):
        self.logger = logger

    def validate_config(self, config_data: Dict[str, Any]) -> bool:
        """
        Validate configuration data structure.

        Args:
            config_data: Configuration data to validate

        Returns:
            True if valid, False otherwise

        Raises:
            ConfigurationValidationError: If validation fails
        """
        try:
            # Check required top-level keys
            required_keys = ['CONFIG_PCI_RAW', 'CONFIG_PCI']
            for key in required_keys:
                if key not in config_data:
                    raise ConfigurationValidationError(
                        f"Missing required configuration key: {key}"
                    )

            # Validate PCI configuration structure
            self._validate_pci_config(config_data['CONFIG_PCI'])

            return True

        except Exception as e:
            raise ConfigurationValidationError(
                f"Configuration validation failed: {e}"
            )

    def _validate_pci_config(self, pci_config: Dict[str, Any]) -> None:
        """Validate PCI configuration structure."""
        if not isinstance(pci_config, dict):
            raise ConfigurationValidationError(
                "CONFIG_PCI must be a dictionary"
            )

        # Add more specific validation rules as needed
        for vid, devices in pci_config.items():
            if not isinstance(devices, dict):
                raise ConfigurationValidationError(
                    f"PCI vendor {vid} must have dictionary of devices"
                )


class ScopeManager:
    """Manages configuration scoping and key filtering."""

    def __init__(self):
        self.parent_keys = [
            'CONFIG_PCI_RAW', 'CONFIG_PCI', 'MEMORY_RANGES', 'MM_MSGBUS',
            'MSGBUS', 'IO', 'MSR', 'MMIO_BARS', 'IO_BARS'
        ]
        self.child_keys = [
            'IMA_REGISTERS', 'REGISTERS', 'CONTROLS', 'LOCKS', 'LOCKEDBY'
        ]

    def apply_scope(self, config_data: Dict[str, Any],
                    scope_pattern: str) -> Dict[str, Any]:
        """
        Apply scoping to configuration data.

        Args:
            config_data: Configuration data to scope
            scope_pattern: Pattern to match for scoping

        Returns:
            Scoped configuration data
        """
        if not scope_pattern:
            return config_data

        scoped_data = {}

        for key, value in config_data.items():
            if self._matches_scope(key, scope_pattern):
                scoped_data[key] = value

        return scoped_data

    def _matches_scope(self, key: str, pattern: str) -> bool:
        """Check if key matches scope pattern."""
        return fnmatch(key, pattern)


scope_name = namedtuple('scope_name', ['vid', 'parent', 'name', 'fields'])
# Python 3.6 namedtuple does not accept defaults
scope_name.__new__.__defaults__ = (None,) * 4

PROC_FAMILY = {}


class Cfg:
    """Main configuration class for CHIPSEC."""

    def __init__(self):
        self.logger = logger()

        # Initialize helper classes
        self.platform_detector = PlatformDetector(self.logger)
        self.config_validator = ConfigurationValidator(self.logger)
        self.scope_manager = ScopeManager()

        # Configuration data structures
        for key in (self.scope_manager.parent_keys +
                    self.scope_manager.child_keys):
            setattr(self, key, {})

        # Initialize configuration state
        self.config_state = ConfigurationState()

        # Initialize platform information
        self.platform_info = PlatformInfo()
        self.pch_info = PCHInfo()
        self.cpu_info = CPUInfo()

        # Legacy attributes for backward compatibility
        self.platform = Platform()
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

        # Legacy properties for backward compatibility
        self.XML_CONFIG_LOADED = False

    @property
    def vid(self) -> int:
        """Legacy property for VID."""
        return self.platform_info.vid

    @vid.setter
    def vid(self, value: int):
        """Legacy setter for VID."""
        self.platform_info.vid = value

    @property
    def did(self) -> int:
        """Legacy property for DID."""
        return self.platform_info.did

    @did.setter
    def did(self, value: int):
        """Legacy setter for DID."""
        self.platform_info.did = value

    @property
    def code(self) -> str:
        """Legacy property for platform code."""
        return self.platform_info.code

    @code.setter
    def code(self, value: str):
        """Legacy setter for platform code."""
        self.platform_info.code = value

    @property
    def longname(self) -> str:
        """Legacy property for platform longname."""
        return self.platform_info.longname

    @longname.setter
    def longname(self, value: str):
        """Legacy setter for platform longname."""
        self.platform_info.longname = value

    @property
    def req_pch(self) -> bool:
        """Legacy property for PCH requirement."""
        return bool(self.platform_info.req_pch)

    @req_pch.setter
    def req_pch(self, value: bool):
        """Legacy setter for PCH requirement."""
        self.platform_info.req_pch = value

    @property
    def rid(self) -> int:
        """Legacy property for RID."""
        return self.platform_info.rid

    @rid.setter
    def rid(self, value: int):
        """Legacy setter for RID."""
        self.platform_info.rid = value

    @property
    def cpuid(self) -> int:
        """Legacy property for CPUID."""
        return self.cpu_info.cpuid

    @cpuid.setter
    def cpuid(self, value: int):
        """Legacy setter for CPUID."""
        self.cpu_info.cpuid = value

    @property
    def mfgid(self) -> str:
        """Legacy property for manufacturer ID."""
        return self.cpu_info.mfgid

    @mfgid.setter
    def mfgid(self, value: str):
        """Legacy setter for manufacturer ID."""
        self.cpu_info.mfgid = value

    @property
    def pch_vid(self) -> int:
        """Legacy property for PCH VID."""
        return self.pch_info.vid

    @pch_vid.setter
    def pch_vid(self, value: int):
        """Legacy setter for PCH VID."""
        self.pch_info.vid = value

    @property
    def pch_did(self) -> int:
        """Legacy property for PCH DID."""
        return self.pch_info.did

    @pch_did.setter
    def pch_did(self, value: int):
        """Legacy setter for PCH DID."""
        self.pch_info.did = value

    @property
    def pch_rid(self) -> int:
        """Legacy property for PCH RID."""
        return self.pch_info.rid

    @pch_rid.setter
    def pch_rid(self, value: int):
        """Legacy setter for PCH RID."""
        self.pch_info.rid = value

    @property
    def pch_code(self) -> str:
        """Legacy property for PCH code."""
        return self.pch_info.code

    @pch_code.setter
    def pch_code(self, value: str):
        """Legacy setter for PCH code."""
        self.pch_info.code = value

    @property
    def pch_longname(self) -> str:
        """Legacy property for PCH longname."""
        return self.pch_info.longname

    @pch_longname.setter
    def pch_longname(self, value: str):
        """Legacy setter for PCH longname."""
        self.pch_info.longname = value

    ###
    # Private functions
    ###
    def _get_vid_from_filename(self, fname):
        search_string = re.compile(r'cfg.[0-9a-fA-F]+')
        match = search_string.search(fname)
        vid = match.group(0)[4:]
        return vid

    def _create_vid(self, vid_str):
        key_list = (self.scope_manager.parent_keys +
                    self.scope_manager.child_keys)
        skip_keys = ['LOCKS']
        if vid_str not in self.CONFIG_PCI:
            for key in key_list:
                if key in skip_keys:
                    continue
                mdict = getattr(self, key)
                mdict[vid_str] = {}

        if vid_str not in self.platform.vendor_list:
            self.platform.add_vendor(Vendor(vid_str))

    ###
    # PCI device tree enumeration
    ###
    def set_pci_data(self, enum_devices):
        if not hasattr(self, 'CONFIG_PCI_RAW'):
            setattr(self, 'CONFIG_PCI_RAW', {})
        for b, d, f, vid, did, rid in enum_devices:
            vid_str = make_hex_key_str(vid)
            did_str = make_hex_key_str(did)
            pci_data = {
                'bus': b,
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

    def set_cpuid(self, cpuid: int) -> None:
        """Set CPU identification information."""
        self.cpu_info.cpuid = cpuid

    def set_mfgid(self, mfgid: str) -> None:
        """Set CPU manufacturer identification."""
        self.cpu_info.mfgid = mfgid

    def set_topology(self, topology: Dict[str, Any]) -> None:
        """
        Set CPU topology information.

        Args:
            topology: Dictionary containing CPU topology data
        """
        if not hasattr(self, 'CPU'):
            setattr(self, 'CPU', {})
        self.CPU.update(topology)
        self.logger.log_hal(f'Added topology to self.CPU\n{self.CPU}')

    def get_chipset_code(self) -> str:
        """Get the current chipset/platform code."""
        return self.platform_info.code

    def get_pch_code(self) -> str:
        """Get the current PCH code."""
        return self.pch_info.code

    def is_pch_req(self) -> bool:
        """Check if PCH is required for this platform."""
        return bool(self.platform_info.req_pch)

    def print_platform_info(self) -> None:
        """Print platform information."""
        self.logger.log(f'Mfg ID  : {self.cpu_info.mfgid}')
        self.logger.log(f'Platform: {self.platform_info.longname}')
        self.logger.log(f'\tCPUID: {self.cpu_info.cpuid:X}')
        self.logger.log(f'\tVID: {self.platform_info.vid:04X}')
        self.logger.log(f'\tDID: {self.platform_info.did:04X}')
        self.logger.log(f'\tRID: {self.platform_info.rid:02X}')

    def print_pch_info(self) -> None:
        """Print PCH information."""
        self.logger.log(f'Platform: {self.pch_info.longname}')
        self.logger.log(f'\tVID: {self.pch_info.vid:04X}')
        self.logger.log(f'\tDID: {self.pch_info.did:04X}')
        self.logger.log(f'\tRID: {self.pch_info.rid:02X}')

    def print_supported_chipsets(self) -> None:
        """Print supported chipsets/platforms."""
        fmt_str = ' {:4} | {:4} | {:14} | {:6} | {:40}'
        self.logger.log('\nSupported platforms:\n')
        self.logger.log(fmt_str.format(
            'VID', 'DID', 'Name', 'Code', 'Long Name'))
        self.logger.log('-' * 85)
        for _vid in sorted(self.proc_dictionary):
            for _did in sorted(self.proc_dictionary[_vid]):
                for item in self.proc_dictionary[_vid][_did]:
                    self.logger.log(fmt_str.format(
                        _vid, _did, item['name'], item['code'].lower(),
                        item['longname'][:40]
                    ))

    ###
    # Private config functions
    ###
    def _get_stage_parsers(self, stage):
        handlers = {}
        for parser in self.parsers:
            if parser.get_stage() != stage:
                continue
            if parser.parser_name() in handlers:
                self.logger.log_debug(f'Tag handlers already contain handlers for parser {parser.parser_name()}')
                # raise CSConfigError(f'Tag handlers already contain handlers for parser {parser.parser_name()}')
                continue
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
                did_str = make_hex_key_str(did)
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
        """Find SKU data with improved error handling."""
        try:
            self.vid_set = dict_ref.keys()
        except KeyError:
            return self.create_unknown_sku()

        possible_skus = self._find_possible_skus_from_detection_value(
            dict_ref, detect_val
        )
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
                self.logger.log_warning(
                    'Multiple SKUs found for detection value, '
                    'using first in the list'
                )
            sku = possible_skus.popitem()[1].popitem()[1].pop()
            sku['longname'] = f"{sku['code']} Generic"
            return sku
        return None

    def _find_did(self, sku):
        """Find the device ID for a given SKU."""
        vid_str = make_hex_key_str(sku['vid'])
        if 'did' in sku and type(sku['did']) is int:
            return sku['did']
        elif 'did' in sku and isinstance(sku['did'], list):
            for did in sku['did']:
                did_str = make_hex_key_str(did)
                if (vid_str in self.CONFIG_PCI_RAW and
                    did_str in self.CONFIG_PCI_RAW[vid_str]):
                    return did
        self.logger.log_warning(
            'Enumerated Platform PCI DID not found in XML Configs. '
            'System info may not be 100% accurate.'
        )
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
        stage_str = 'core' if stage in [Stage.CORE_SUPPORT, Stage.REGISTER] else 'custom'
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
            self.load_extra = [config_data(None, None, os.path.join(config_path, f), None, None) for f in sorted(os.listdir(config_path))
                               if fnmatch(f, '*.xml')]
        elif os.path.isdir(config_path) and filename:
            self.load_extra = [config_data(None, None, os.path.join(config_path, f), None, None) for f in sorted(os.listdir(config_path))
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
                             for f in sorted(os.scandir(root_path), key=lambda x: x.name.lower())
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
        try:
            for vid in self.CONFIG_PCI_RAW:
                for did in self.CONFIG_PCI_RAW[vid]:
                    if 0 in self.CONFIG_PCI_RAW[vid][did].cfg['bus'] and self.CONFIG_PCI_RAW[vid][did].cfg['dev'] == 0 and self.CONFIG_PCI_RAW[vid][did].cfg['fun'] == 0:
                        return self.CONFIG_PCI_RAW[vid][did].cfg
        except (TypeError, KeyError):
            pass
        return {'vid': 0xFFFF, 'did': 0xFFFF, 'rid': 0xFF}

    def add_memory_range(self, mem_range_obj: Dict) -> None:
        """Add memory range configuration."""
        self.MEMORY_RANGES[mem_range_obj['vid_str']][mem_range_obj['name']] = mem_range_obj

    def platform_detection(self, proc_code, pch_code, cpuid):
        """Detect platform with improved error handling."""
        # Detect processor files
        self.cpuid = cpuid
        sku = self._find_sku_data(self.proc_dictionary, proc_code, cpuid)
        if sku:
            self.vid = sku['vid']
            self.did = self._find_did(sku)
            self.code = sku['code']
            self.longname = sku['longname']
            self.req_pch = sku['req_pch']

            if self.did == 0xFFFF:
                dev000 = self.get_dev_from_bdf_000()
                self.did = dev000['did']
                self.rid = dev000['rid']
            elif not proc_code:
                try:
                    vid_str = make_hex_key_str(self.vid)
                    did_str = make_hex_key_str(self.did)
                    if (vid_str in self.CONFIG_PCI_RAW and
                            did_str in self.CONFIG_PCI_RAW[vid_str]):
                        pci_obj = self.CONFIG_PCI_RAW[vid_str][did_str]
                        if hasattr(pci_obj, 'get_rid'):
                            self.rid = pci_obj.get_rid(0, 0, 0)
                        else:
                            self.rid = 0xFF
                    else:
                        dev000 = self.get_dev_from_bdf_000()
                        self.rid = dev000['rid']
                except (KeyError, AttributeError, TypeError):
                    dev000 = self.get_dev_from_bdf_000()
                    self.rid = dev000['rid']
            else:
                raise CSConfigError('There is already a CPU detected, '
                                    'are you adding a new config?')
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
            self.pch_longname = sku['longname']

            if not pch_code:
                try:
                    vid_str = make_hex_key_str(self.pch_vid)
                    did_str = make_hex_key_str(self.pch_did)
                    if (vid_str in self.CONFIG_PCI_RAW and
                            did_str in self.CONFIG_PCI_RAW[vid_str]):
                        pci_obj = self.CONFIG_PCI_RAW[vid_str][did_str]
                        if hasattr(pci_obj, 'instances'):
                            for cfg_data in pci_obj.instances.values():
                                if (0x1f == cfg_data.dev and
                                    0x0 == cfg_data.fun):
                                    self.pch_rid = cfg_data.rid
                                    break
                        else:
                            self.pch_rid = 0xFF
                    else:
                        self.pch_rid = 0xFF
                except (KeyError, AttributeError, TypeError):
                    self.pch_rid = 0xFF
            else:
                raise CSConfigError('There is already a PCH detected, '
                                    'are you adding a new config?')

        # Create XML file load list
        if self.code:
            self.load_list.extend(self.platform_xml_files.get(self.code, []))
        if self.pch_code:
            self.load_list.extend(
                self.platform_xml_files.get(self.pch_code, [])
            )
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
        self._load_sec_configs(sec_load_list, Stage.REGISTER)
        self._load_sec_configs(sec_load_list, Stage.CUST_SUPPORT)
        if self.load_extra:
            self._load_sec_configs(self.load_extra, Stage.EXTRA)

    ###
    # Scoping Functions
    ###
    def set_scope(self, scope: Dict[str, str]) -> None:
        """Set the current scope for register access."""
        self.scope.update(scope)

    def clear_scope(self) -> None:
        """Clear the current scope for register access."""
        self.scope = {None: ''}

    def get_scope(self, name: str) -> str:
        """Get scope for a given name."""
        if '.' in name:
            return ''
        elif name in self.scope:
            return self.scope[name]
        else:
            return self.scope[None]

    def convert_internal_scope(self, scope, name):
        if scope:
            sname = scope + '.' + name
        else:
            sname = name
        return scope_name(*(sname.split('.', 3)))

    def convert_platform_scope(self, scope, name):
        if scope:
            sname = scope + '.' + name
        else:
            sname = name
        return sname.split('.')

    def get_objlist(self, name: str):
        scope = self.get_scope(name)
        fullscope = self.convert_platform_scope(scope, name)
        return self.platform.get_matches_from_scope(fullscope)

    def get_reglist(self, name: str):
        scope = self.get_scope(name)
        fullscope = self.convert_platform_scope(scope, name)
        return self.platform.get_register_matches_from_scope(fullscope)

    def __add_obj_to_regdef(self, reg_def, obj):
        if isinstance(obj, Iterable):
            reg_def.extend(obj)
        else:
            reg_def.append(obj)
        return reg_def

    # 'vid', 'parent', 'register', 'field'; register.get_obj("8086.*.FREG*_BIOS")
    def get_objlist_from_scope(self, objdict: dict, scope: scope_name):
        reg_def = ObjList()
        vid = scope.vid.replace('*', '.*')
        dict_vids = [vid] if '*' not in vid and vid in objdict.keys() else objdict.keys()
        for dict_vid in dict_vids:
            if re.match(vid, dict_vid):
                parent = scope.parent.replace('*', '.*')
                dict_parents = [parent] if '*' not in parent and parent in objdict[dict_vid].keys() else objdict[dict_vid].keys()
                for dict_parent in dict_parents:
                    if re.match(parent, dict_parent):
                        if scope.name:
                            name = scope.name.replace('*', '.*')
                            dict_names = [name] if '*' not in name and name in objdict[dict_vid][dict_parent].keys() else objdict[dict_vid][dict_parent].keys()
                            for dict_name in dict_names:
                                if re.match(name, dict_name):
                                    self.__add_obj_to_regdef(reg_def, objdict[dict_vid][dict_parent][dict_name])
                        else:

                            self.__add_obj_to_regdef(reg_def, objdict[dict_vid][dict_parent])

        return reg_def

    def get_scopelist_from_full_name(self, full_name):
        return full_name.split('.')

    # TODO: Review for correctness compared to chipsec/library/control.py:get_list_by_name()
    # def get_control_obj(self, control_name, instance=None):
    #     controls = ObjList()
    #     if control_name in self.CONTROLS.keys():
    #         if instance is not None and 'obj' in self.CONTROLS[control_name].keys():
    #             return self.CONTROLS[control_name]['obj'][instance]
    #         controls.extend(self.CONTROLS[control_name]['obj'])
    #     return controls

    # TODO: Review for correctness compared to chipsec/library/register.py:has_field()
    # def register_has_field(self, reg_name, field_name):
    #     scope = self.get_scope(reg_name)
    #     vid, device, register, _ = self.convert_internal_scope(scope, reg_name)
    #     try:
    #         reg_def = self.REGISTERS[vid][device][register]
    #     except KeyError:
    #         return False
    #     if 'FIELDS' not in reg_def:
    #         return False
    #     return (field_name in reg_def['FIELDS'])

    def validate_and_load_config(self, config_path: str) -> None:
        """Validate and load configuration with better error handling."""
        try:
            if not os.path.exists(config_path):
                raise ParserLoadError(f"Configuration path does not exist: {config_path}")

            # Load configuration files
            self._load_config_files(config_path)

            # Validate loaded configuration
            config_data = {
                'CONFIG_PCI_RAW': self.CONFIG_PCI_RAW,
                'CONFIG_PCI': self.CONFIG_PCI
            }

            if self.config_validator.validate_config(config_data):
                self.logger.log_debug("Configuration validation passed")

        except (ParserLoadError, ConfigurationValidationError) as e:
            self.logger.log_error(f"Configuration loading failed: {e}")
            raise
        except Exception as e:
            self.logger.log_error(f"Unexpected error loading configuration: {e}")
            raise ParserLoadError(f"Failed to load configuration: {e}")

    def _load_config_files(self, config_path: str) -> None:
        """Load configuration files from path."""
        # Implementation for loading config files
        pass

    def get_platform_info(self) -> PlatformInfo:
        """Get current platform information."""
        return self.platform_info

    def get_pch_info(self) -> PCHInfo:
        """Get current PCH information."""
        return self.pch_info

    def get_cpu_info(self) -> CPUInfo:
        """Get current CPU information."""
        return self.cpu_info

    def get_config_state(self) -> ConfigurationState:
        """Get current configuration state."""
        return self.config_state

    def is_platform_detected(self) -> bool:
        """Check if platform has been successfully detected."""
        return (self.config_state.platform_detected and
                self.platform_info.code != CHIPSET_CODE_UNKNOWN)

    def is_config_validated(self) -> bool:
        """Check if configuration has been validated."""
        return self.config_state.validation_passed

    def reset_configuration(self) -> None:
        """Reset configuration to initial state."""
        self.config_state = ConfigurationState()
        self.platform_info = PlatformInfo()
        self.pch_info = PCHInfo()
        self.cpu_info = CPUInfo()

        # Clear configuration data
        for key in (self.scope_manager.parent_keys +
                    self.scope_manager.child_keys):
            setattr(self, key, {})

    def enhanced_platform_detection(self, proc_code: str = None,
                                   pch_code: str = None,
                                   cpuid: int = 0) -> None:
        """
        Enhanced platform detection with better error handling and validation.

        Args:
            proc_code: Platform code to force detection
            pch_code: PCH code to force detection
            cpuid: CPU identification
        """
        try:
            # Update CPU information
            self.set_cpuid(cpuid)

            # Mark detection as started
            self.config_state.platform_detected = False

            # Detect processor files using new architecture
            proc_sku = self._find_sku_data(self.proc_dictionary, proc_code, cpuid)
            if proc_sku:
                self.platform_info.vid = proc_sku['vid']
                self.platform_info.did = self._find_did(proc_sku)
                if self.platform_info.did == 0xFFFF:
                    dev000 = self.get_dev_from_bdf_000()
                    self.platform_info.did = dev000['did']
                self.platform_info.code = proc_sku['code']

                if not proc_code:
                    vid_str = make_hex_key_str(self.platform_info.vid)
                    did_str = make_hex_key_str(self.platform_info.did)
                    try:
                        self.platform_info.rid = self.CONFIG_PCI_RAW[vid_str][did_str].get_rid(0, 0, 0)
                    except (KeyError, AttributeError):
                        self.platform_info.rid = 0xFF

                self.platform_info.longname = proc_sku['longname']
                self.platform_info.req_pch = proc_sku['req_pch']
            else:
                # Use fallback detection
                dev000 = self.get_dev_from_bdf_000()
                self.platform_info.vid = dev000['vid']
                self.platform_info.did = dev000['did']
                self.platform_info.rid = dev000['rid']

            # Detect PCH files using new architecture
            pch_sku = self._find_sku_data(self.pch_dictionary, pch_code)
            if pch_sku:
                self.pch_info.vid = pch_sku['vid']
                self.pch_info.did = self._find_did(pch_sku)
                self.pch_info.code = pch_sku['code']

                if not pch_code:
                    vid_str = make_hex_key_str(self.pch_info.vid)
                    did_str = make_hex_key_str(self.pch_info.did)
                    try:
                        for cfg_data in self.CONFIG_PCI_RAW[vid_str][did_str].instances.values():
                            if 0x1f == cfg_data.dev and 0x0 == cfg_data.fun:
                                self.pch_info.rid = cfg_data.rid
                                break
                    except (KeyError, AttributeError):
                        self.pch_info.rid = 0xFF

                self.pch_info.longname = pch_sku['longname']

            # Create XML file load list
            if self.platform_info.code:
                self.load_list.extend(self.platform_xml_files.get(self.platform_info.code, []))
            if self.pch_info.code:
                self.load_list.extend(self.platform_xml_files.get(self.pch_info.code, []))
            if 'devices' in self.platform_xml_files:
                self.load_list.extend(self.platform_xml_files['devices'])

            # Mark as successfully detected
            self.config_state.platform_detected = True

        except Exception as e:
            self.logger.log_error(f"Enhanced platform detection failed: {e}")
            raise PlatformDetectionError(f"Platform detection failed: {e}")
