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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.
#
# Contact information:
# chipsec@intel.com

"""
Core parser helper utilities and base classes.

This module provides common functionality for CHIPSEC configuration parsers,
including XML data conversion, error handling, and base classes.
"""

import os
from dataclasses import dataclass
from typing import Dict, List, Any, Set, Optional, TYPE_CHECKING
from xml.etree.ElementTree import Element

from chipsec.parsers import config_data
from chipsec.library.display import make_dict_hex
from chipsec.library.logger import logger

if TYPE_CHECKING:
    from chipsec.config import ChipsecConfig


class ParserError(Exception):
    """Base exception for parser-related errors."""
    pass


class XMLConversionError(ParserError):
    """Exception raised when XML data conversion fails."""
    pass


class ConfigurationError(ParserError):
    """Exception raised when configuration processing fails."""
    pass


@dataclass
class ConversionRules:
    """Rules for converting XML attributes to appropriate Python types."""

    int_keys: Set[str]
    bool_keys: Set[str]
    int_list_keys: Set[str]
    str_list_keys: Set[str]
    range_list_keys: Set[str]

    @classmethod
    def default_rules(cls, did_is_range: bool = False) -> 'ConversionRules':
        """Create default conversion rules."""
        int_keys = {
            'dev', 'fun', 'vid', 'did', 'rid', 'offset',
            'bit', 'size', 'port', 'msr', 'value', 'address',
            'fixed_address', 'base_align', 'align_bits', 'mask',
            'reg_align', 'limit_align', 'regh_align', 'default',
            'limit', 'enable_bit'
        }

        range_list_keys = {'detection_value'}

        if did_is_range:
            int_keys.discard('did')
            range_list_keys.add('did')

        return cls(
            int_keys=int_keys,
            bool_keys={'req_pch'},
            int_list_keys={'bus'},
            str_list_keys={'config'},
            range_list_keys=range_list_keys
        )


class XMLConfigConverter:
    """Handles conversion of XML node attributes to Python data structures."""

    def __init__(self, rules: Optional[ConversionRules] = None):
        """Initialize converter with conversion rules."""
        self.rules = rules or ConversionRules.default_rules()
        self.logger = logger()

    def convert_node(self, xml_node: Element,
                     did_is_range: bool = False) -> Dict[str, Any]:
        """
        Convert XML node attributes to appropriate Python types.

        Args:
            xml_node: XML element to convert
            did_is_range: Whether 'did' attribute should be treated as range

        Returns:
            Dictionary with converted attributes

        Raises:
            XMLConversionError: If conversion fails
        """
        if xml_node is None:
            raise XMLConversionError("XML node cannot be None")

        # Update rules if did_is_range differs from initialization
        if did_is_range and 'did' in self.rules.int_keys:
            rules = ConversionRules.default_rules(did_is_range=True)
        else:
            rules = self.rules

        node_data = {}

        try:
            for key, value in xml_node.attrib.items():
                node_data[key] = self._convert_attribute(key, value, rules)
        except Exception as e:
            raise XMLConversionError(f"Failed to convert XML node: {e}") from e

        return node_data

    def _convert_attribute(self, key: str, value: str,
                           rules: ConversionRules) -> Any:
        """Convert a single XML attribute based on conversion rules."""
        try:
            if key in rules.int_keys:
                return int(value, 0)  # Auto-detect base (0x for hex, etc.)
            elif key in rules.int_list_keys:
                return [int(value, 0)]
            elif key in rules.str_list_keys:
                return [x.strip() for x in value.split(',')]
            elif key in rules.range_list_keys:
                return self._parse_range_data(value)
            elif key in rules.bool_keys:
                return value.lower() == 'true'
            else:
                return value
        except ValueError as e:
            msg = f"Failed to convert attribute {key}='{value}': {e}"
            self.logger.log_warning(msg)
            return value  # Return original value if conversion fails

    def _parse_range_data(self, value: str) -> List[int]:
        """Parse range data from comma-separated string."""
        int_items = []

        try:
            for item in value.split(','):
                item = item.strip()
                if item.upper().endswith('*'):
                    # Wildcard range (e.g., "0x1000*" -> 0x1000-0x100F)
                    base = int(item.replace('*', '0'), 0)
                    int_items.extend(range(base, base + 0x10))
                elif '-' in item:
                    # Explicit range (e.g., "0x1000-0x1010")
                    item_min, item_max = item.split('-', 1)
                    min_val = int(item_min, 0)
                    max_val = int(item_max, 0)
                    int_items.extend(range(min_val, max_val + 1))
                else:
                    # Single value
                    int_items.append(int(item, 0))
        except ValueError as e:
            msg = f"Invalid range data '{value}': {e}"
            raise XMLConversionError(msg) from e

        return int_items


class CoreParserHelper:
    """Helper class for common parsing operations."""

    def __init__(self, config: 'ChipsecConfig'):
        """Initialize helper with configuration object."""
        self.logger = logger()
        self.cfg = config
        self.converter = XMLConfigConverter()

    def process_config_complex(self,
                               stage_data: Any,
                               dev_name: str,
                               dev_attr: Any,
                               component: Optional[str] = None) -> List[config_data]:
        """
        Process complex configuration with error handling.

        Args:
            stage_data: Stage processing data
            dev_name: Device name
            dev_attr: Device attributes
            component: Optional component name

        Returns:
            List of configuration data objects
        """
        ret_val = []

        try:
            if not hasattr(dev_attr, 'config') or not dev_attr.config:
                self.logger.log_debug(f"No config found for device {dev_name}")
                return ret_val

            attrs = {'tmp': getattr(dev_attr, 'instances', {})}

            for fxml in dev_attr.config:
                try:
                    cfg_file = self._process_config_path(fxml)
                    base_dir = os.path.dirname(stage_data.xml_file)
                    cfg_path = os.path.join(base_dir, cfg_file)

                    if not os.path.exists(cfg_path):
                        msg = f"Configuration file not found: {cfg_path}"
                        self.logger.log_warning(msg)
                        continue

                    ret_val.append(config_data(
                        stage_data.vid_str,
                        dev_name,
                        cfg_path,
                        component,
                        attrs
                    ))
                except Exception as e:
                    msg = f"Failed to process config {fxml}: {e}"
                    self.logger.log_error(msg)

        except Exception as e:
            msg = f"Failed to process complex config for {dev_name}: {e}"
            self.logger.log_error(msg)

        return ret_val

    def _process_config_path(self, fxml: str) -> str:
        """Convert dot-separated config path to file system path."""
        return fxml.replace('.', os.path.sep, fxml.count('.') - 1)

    def handle_bars(self,
                    et_node: Element,
                    stage_data: Any,
                    dest: Dict[str, Any],
                    cfg_obj: type) -> List[config_data]:
        """
        Handle multiple bar configurations.

        Args:
            et_node: XML element containing bar definitions
            stage_data: Stage processing data
            dest: Destination dictionary for bar data
            cfg_obj: Configuration object class

        Returns:
            List of configuration data objects
        """
        ret_val = []

        try:
            for bar in et_node.iter('bar'):
                try:
                    result = self.handle_bar(bar, stage_data, dest, cfg_obj)
                    ret_val.extend(result)
                except Exception as e:
                    self.logger.log_error(f"Failed to process bar: {e}")
        except Exception as e:
            self.logger.log_error(f"Failed to handle bars: {e}")

        return ret_val

    def handle_bar(self,
                   et_node: Element,
                   stage_data: Any,
                   dest: Dict[str, Any],
                   cfg_obj: type) -> List[config_data]:
        """
        Handle single bar configuration with comprehensive error handling.

        Args:
            et_node: XML element for bar
            stage_data: Stage processing data
            dest: Destination dictionary for bar data
            cfg_obj: Configuration object class

        Returns:
            List of configuration data objects
        """
        ret_val = []

        try:
            bar_attr = self.converter.convert_node(et_node, True)

            # Validate required attributes
            if 'name' not in bar_attr:
                self.logger.log_error("Missing 'name' attribute in bar config")
                return ret_val

            device_keys = ['device', 'component']
            has_device = any(key in bar_attr for key in device_keys)
            if not has_device and not stage_data.dev_name:
                msg = f"Missing device/component info for bar {bar_attr['name']}"
                self.logger.log_error(msg)
                return ret_val

            bar_name = bar_attr['name']
            dev_name = self._determine_device_name(bar_attr, stage_data)
            bar_attr['device'] = dev_name

            # Process bar configuration
            self.process_bar(stage_data.vid_str, bar_name, bar_attr,
                           dest, cfg_obj)

            # Process additional configurations
            if (stage_data.vid_str in dest and
                dev_name in dest[stage_data.vid_str] and
                bar_name in dest[stage_data.vid_str][dev_name]):

                bar_obj = dest[stage_data.vid_str][dev_name][bar_name]
                ret_val.extend(self.process_config_complex(
                    stage_data, bar_name, bar_obj, dev_name))

            # Log successful processing
            hex_dict = make_dict_hex(bar_attr)
            self.logger.log_debug(f"    + {bar_name:16}: {hex_dict}")

        except Exception as e:
            self.logger.log_error(f"Failed to handle bar: {e}")

        return ret_val

    def _determine_device_name(self, bar_attr: Dict[str, Any],
                               stage_data: Any) -> str:
        """Determine device name from bar attributes or stage data."""
        if 'device' in bar_attr:
            return bar_attr['device']
        elif 'component' in bar_attr:
            return bar_attr['component']
        elif hasattr(stage_data, 'dev_name') and stage_data.dev_name:
            return stage_data.dev_name
        else:
            raise ConfigurationError("Cannot determine device name for bar")

    def process_bar(self,
                    vid_str: str,
                    bar_name: str,
                    bar_attr: Dict[str, Any],
                    dest: Dict[str, Any],
                    cfg_obj: type) -> None:
        """
        Process bar configuration with improved error handling.

        Args:
            vid_str: Vendor ID string
            bar_name: Bar name
            bar_attr: Bar attributes
            dest: Destination dictionary
            cfg_obj: Configuration object class
        """
        try:
            # Process register references
            register_fields = ['register', 'base_reg', 'mmio_base',
                             'limit_register']
            for field in register_fields:
                if field in bar_attr:
                    reg_name = self.make_reg_name(vid_str, bar_attr['device'],
                                                bar_attr[field])
                    bar_attr[field] = reg_name

            # Initialize nested dictionaries
            self._ensure_nested_dict_structure(dest, vid_str, bar_attr['device'])

            device_dest = dest[vid_str][bar_attr['device']]

            # Handle existing configuration
            if bar_name in device_dest and 'config' in bar_attr:
                device_dest[bar_name].add_config(bar_attr['config'])
            else:
                # Create new bar object
                pci_config = self.cfg.CONFIG_PCI
                if (vid_str in pci_config and
                    bar_attr['device'] in pci_config[vid_str]):
                    instances = pci_config[vid_str][bar_attr['device']].instances
                    bar_attr['ids'] = instances.values()

                bar_obj = cfg_obj(bar_attr)
                device_dest[bar_name] = bar_obj

                # Update platform configuration
                try:
                    vendor = self.cfg.platform.get_vendor(vid_str)
                    ip = vendor.get_ip(bar_attr['device'])
                    ip.add_bar(bar_name, bar_obj)
                except Exception as e:
                    msg = f"Failed to update platform configuration: {e}"
                    self.logger.log_warning(msg)

        except Exception as e:
            msg = f"Failed to process bar {bar_name}: {e}"
            self.logger.log_error(msg)
            raise ConfigurationError(f"Bar processing failed: {e}") from e

    def _ensure_nested_dict_structure(self, dest: Dict[str, Any],
                                      vid_str: str, device: str) -> None:
        """Ensure nested dictionary structure exists."""
        if vid_str not in dest:
            dest[vid_str] = {}
        if device not in dest[vid_str]:
            dest[vid_str][device] = {}

    def make_reg_name(self, vid_str: str, device_name: str, reg_name: str) -> str:
        """Create fully qualified register name."""
        if not all([vid_str, device_name, reg_name]):
            raise ValueError("All components must be non-empty")
        return '.'.join([vid_str, device_name, reg_name])


# Backward compatibility - maintain original function name
def config_convert_data(xml_node: Element,
                        did_is_range: bool = False) -> Dict[str, Any]:
    """
    Legacy function for XML node conversion.

    Deprecated: Use XMLConfigConverter.convert_node() instead.
    """
    converter = XMLConfigConverter()
    return converter.convert_node(xml_node, did_is_range)


# Import alias for _get_range_data function (backward compatibility)
def _get_range_data(xml_node: Element, attr: str) -> List[int]:
    """Legacy function for range data parsing."""
    converter = XMLConfigConverter()
    value = xml_node.attrib.get(attr, '')
    return converter._parse_range_data(value)
