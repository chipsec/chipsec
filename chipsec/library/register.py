# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2024, Intel Corporation
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

"""
Main functionality to read/write configuration registers.

This module provides the primary register interface for CHIPSEC, allowing
access to various types of hardware registers including PCI configuration,
MMIO, MSR, and others. It serves as the main entry point for register
operations and coordinates with the specialized register interface classes.
"""

from typing import Any, Dict, List, Optional

from chipsec.parsers import BaseConfigHelper
from chipsec.library.logger import logger
from chipsec.library.bits import set_bits, get_bits, make_mask
from chipsec.library.exceptions import (CSReadError, RegisterNotFoundError)
from chipsec.library.registers.io import IO
from chipsec.library.registers.iobar import IOBar
from chipsec.library.registers.memory import Memory
from chipsec.library.registers.mm_msgbus import MMMsgBus
from chipsec.library.registers.mmcfg import MMCfg
from chipsec.library.registers.mmio import MMIO
from chipsec.library.registers.msgbus import MsgBus
from chipsec.library.registers.msr import MSR
from chipsec.library.registers.pcicfg import PCICfg


class RegisterType:
    """
    Constants defining the supported register types in CHIPSEC.

    These constants are used to identify different types of hardware
    registers and their access methods.
    """
    PCICFG = 'pcicfg'
    MMCFG = 'mmcfg'
    MMIO = 'mmio'
    MSR = 'msr'
    PORTIO = 'io'
    IOBAR = 'iobar'
    MSGBUS = 'msgbus'
    MM_MSGBUS = 'mm_msgbus'
    MEMORY = 'memory'
    IMA = 'indirect'


class Register:
    """
    Main register interface class for CHIPSEC.

    This class provides a unified interface for accessing various types of
    hardware registers. It instantiates and coordinates with specialized
    register interface classes for different register types.
    """

    def __init__(self, cs: Any) -> None:
        """
        Initialize the Register interface.

        Args:
            cs: Chipset interface object
        """
        self.cs = cs
        self.io = IO(cs)
        self.iobar = IOBar(cs)
        self.memory = Memory(cs)
        self.mm_msgbus = MMMsgBus(cs)
        self.mmcfg = MMCfg(cs)
        self.mmio = MMIO(cs)
        self.msgbus = MsgBus(cs)
        self.msr = MSR(cs)
        self.pcicfg = PCICfg(cs)

    def is_defined(self, reg_name: str) -> bool:
        """Checks if register is defined in the XML config"""
        try:
            reglist = self.cs.Cfg.get_reglist(reg_name)
        except RegisterNotFoundError:
            return False
        return len(reglist) > 0

    def _get_pci_def(
        self, reg_def: Dict[str, Any], vid: str, dev_name: str
    ) -> Dict[str, Any]:
        """Return Bus Dev Fun of a PCI register"""
        dev = self.cs.Cfg.CONFIG_PCI[vid][dev_name]
        reg_def['bus'] = dev.bus
        reg_def['dev'] = dev.dev
        reg_def['fun'] = dev.fun
        return reg_def

    def _get_mmmsgbus_def(
        self, reg_def: Dict[str, Any], vid: str, dev_name: str
    ) -> Dict[str, Any]:
        """Return port address of a MM_MSGBUS register"""
        dev = self.cs.Cfg.MM_MSGBUS[vid][dev_name]
        reg_def['port'] = dev['port']
        return reg_def

    def _get_indirect_def(
        self, reg_def: Dict[str, Any], vid: str, dev_name: str
    ) -> Dict[str, Any]:
        """Return base index data of a IMA register"""
        dev = self.cs.Cfg.IMA_REGISTERS[vid][dev_name]
        if 'base' in dev:
            reg_def['base'] = dev['base']
        else:
            reg_def['base'] = '0'
        if dev['index'] in self.cs.Cfg.REGISTERS[vid][dev_name]:
            reg_def['index'] = dev['index']
        else:
            logger().log_error(f'Index register {dev["index"]} not found')
        if dev['data'] in self.cs.Cfg.REGISTERS[vid][dev_name]:
            reg_def['data'] = dev['data']
        else:
            logger().log_error(f'Data register {dev["data"]} not found')
        return reg_def

    def get_def(self, reg_name: str) -> Dict[str, Any]:
        """
        Return complete register definition.

        Args:
            reg_name: Name of the register to retrieve

        Returns:
            Dictionary containing the complete register definition
        """
        scope = self.cs.Cfg.get_scope(reg_name)
        fullscope = self.cs.Cfg.convert_platform_scope(scope, reg_name)
        vid = fullscope[0]
        dev_name = fullscope[1]
        # Get register definition from platform scope
        reg_def = self.cs.Cfg.platform.get_register_from_scope(fullscope)
        if isinstance(reg_def, list):
            reg_def = reg_def[0]

        # Map register object types to their definition processors
        def_type_map = {
            RegisterType.PCICFG: self._get_pci_def,
            RegisterType.MMCFG: self._get_pci_def,
            RegisterType.MM_MSGBUS: self._get_mmmsgbus_def,
            RegisterType.IMA: self._get_indirect_def,
        }

        # Check if reg_def has a register_type attribute or method
        if hasattr(reg_def, 'register_type'):
            reg_type = reg_def.register_type
        elif hasattr(reg_def, 'get_type'):
            reg_type = reg_def.get_type()
        else:
            # Fallback to type-based mapping
            reg_type = type(reg_def).__name__.lower()

        if reg_type in def_type_map:
            return def_type_map[reg_type](reg_def, vid, dev_name)
        else:
            return reg_def

    def get_list_by_name(self, reg_name: str) -> 'ObjList':
        """
        Get list of register objects by name.

        Args:
            reg_name: Name of the register

        Returns:
            List of register objects matching the name
        """
        reglist = self.cs.Cfg.get_reglist(reg_name).filter_enabled()
        logger().log_verbose(f" Got reg list: {', '.join([reg.name for reg in reglist])}")
        return reglist

    def get_list_by_name_without_scope(self, reg_name: str) -> 'ObjList':
        """
        Get register list without scope prefix.

        This method searches for registers across all vendors and devices
        using the platform structure from the refactored configuration system.
        It performs a comprehensive search through the platform structure and
        falls back to legacy methods if needed.

        Args:
            reg_name: Name of the register without scope

        Returns:
            List of register objects matching the name across all scopes
        """
        result_list = ObjList()

        # Check that the configuration is initialized
        if not hasattr(self.cs, 'Cfg'):
            logger().log_warning("Configuration not initialized")
            return result_list

        # Use the platform structure to search across all vendors and devices
        if hasattr(self.cs.Cfg, 'platform') and self.cs.Cfg.platform:
            # Log diagnostic info at debug level
            platform = self.cs.Cfg.platform
            if hasattr(platform, 'vendor_list') and platform.vendor_list:
                vendor_count = len(platform.vendor_list)
                logger().log_debug(f"Searching {vendor_count} vendors in platform structure")

                # Search through all vendor/device combinations
                for vendor_id in platform.vendor_list:
                    vendor = platform.get_vendor(vendor_id)

                    # Check if vendor.devices exists
                    if hasattr(vendor, 'ip_list') and vendor.ip_list:
                        for ip_id in vendor.ip_list:
                            ip = vendor.get_ip(ip_id)

                            if hasattr(ip, 'bar_list') and ip.bar_list:
                                for bar_id in ip.bar_list:
                                    # Check for registers
                                    bar = ip.get_bar(bar_id)
                                    has_registers = (hasattr(bar, 'register_list') and
                                                    bar.register_list)

                                    if has_registers and reg_name in bar.register_list:
                                        # Found the register, add all instances
                                        reg_objects = bar.register_list[reg_name]
                                        logger().log_debug(
                                            f"Found register {reg_name} in {vendor_id}.{ip_id}.{bar_id}")
                                        if isinstance(reg_objects, list):
                                            result_list.extend(reg_objects)
                                        else:
                                            result_list.append(reg_objects) 
                            # Check for registers
                            has_registers = (hasattr(ip, 'register_list') and
                                            ip.register_list)

                            if has_registers and reg_name in ip.register_list:
                                # Found the register, add all instances
                                reg_objects = ip.register_list[reg_name]
                                logger().log_debug(
                                    f"Found register {reg_name} in {vendor_id}.{ip_id}")

                                if isinstance(reg_objects, list):
                                    result_list.extend(reg_objects)
                                else:
                                    result_list.append(reg_objects)
            else:
                logger().log_debug("No vendors in platform structure")
        else:
            logger().log_debug("Platform structure not available")

        # If no results found in platform structure, try fallback methods
        if not result_list:
            logger().log_debug(
                f"No results found for {reg_name} in platform structure, trying fallbacks")

            # Try different fallback approaches
            try:
                # First try direct wildcard approach
                fallback_result = self.cs.Cfg.get_reglist('*.*.' + reg_name)
                if fallback_result:
                    logger().log_debug(
                        f"Found {len(fallback_result)} results with '*.*.' fallback")
                    result_list.extend(fallback_result)
            except Exception as e:
                logger().log_debug(f"First fallback failed: {str(e)}")

                try:
                    # Second approach: more flexible wildcard pattern
                    fallback_result = self.cs.Cfg.get_reglist('*.' + reg_name)
                    if fallback_result:
                        logger().log_debug(
                            f"Found {len(fallback_result)} results with '*.' fallback")
                        result_list.extend(fallback_result)
                except Exception as e2:
                    logger().log_debug(f"Second fallback failed: {str(e2)}")

                    try:
                        # Legacy approach: check REGISTERS structure directly
                        if hasattr(self.cs.Cfg, 'REGISTERS'):
                            possible_regs = []

                            # Search through legacy REGISTERS structure
                            for vid in self.cs.Cfg.REGISTERS.keys():
                                for dev in self.cs.Cfg.REGISTERS[vid].keys():
                                    if reg_name in self.cs.Cfg.REGISTERS[vid][dev]:
                                        reg_path = f"{vid}.{dev}.{reg_name}"
                                        possible_regs.append(reg_path)

                            # Get register objects for each path found
                            for reg_path in possible_regs:
                                try:
                                    reg_objs = self.cs.Cfg.get_reglist(reg_path)
                                    logger().log_debug(
                                        f"Found register via legacy lookup: {reg_path}")
                                    result_list.extend(reg_objs)
                                except Exception:
                                    # Ignore errors for individual registers
                                    pass
                    except Exception as e3:
                        logger().log_debug(f"All fallbacks failed: {str(e3)}")

        # Log summary
        if result_list:
            logger().log_debug(
                f"Found {len(result_list)} registers for {reg_name} without scope")
        else:
            logger().log_debug(f"No registers found for {reg_name} without scope")

        return result_list

    def get_instance_by_name(self, reg_name: str,
                             instance: Any) -> Optional[Any]:
        """
        Get specific register instance by name and instance identifier.

        Args:
            reg_name: Name of the register
            instance: Instance identifier

        Returns:
            Register instance if found, NullRegister object if not found
        """
        try:
            for reg_obj in self.cs.Cfg.get_reglist(reg_name):
                if reg_obj.get_instance() == instance:
                    return reg_obj
        except RegisterNotFoundError:
            logger().log_error(f'Register {reg_name} not found')

        # Return a null register object instead of None for better error handling
        return NullRegister(reg_name, instance)

    def has_field(self, reg_name: str, field_name: str) -> bool:
        """Checks if the register has specific field"""
        field_name = field_name.upper()
        try:
            reg_defs = self.cs.Cfg.get_reglist(reg_name)
        except RegisterNotFoundError:
            return False
        try:
            return bool(reg_defs) and all([field_name in reg_def.fields for reg_def in reg_defs])
        except KeyError:
            return False

    def get_match(self, name: str) -> List[str]:
        """
        Get registers and fields matching a specific pattern.

        Uses the modern platform structure to search for matching registers
        across all vendors and devices.

        Args:
            name: Pattern to match (can include wildcards)

        Returns:
            List of matching register.field identifiers
        """
        vid, device, register, field = self.cs.Cfg.convert_internal_scope(
            '', name)
        ret = []

        # Use platform structure if available
        if hasattr(self.cs.Cfg, 'platform') and self.cs.Cfg.platform:
            # Get vendor list
            if vid is None or vid == '*':
                vendor_list = list(self.cs.Cfg.platform.vendors.keys())
            else:
                vendor_list = [vid] if vid in self.cs.Cfg.platform.vendors else []

            for v in vendor_list:
                vendor = self.cs.Cfg.platform.vendors[v]

                # Get device list for this vendor
                if device is None or device == '*':
                    device_list = list(vendor.devices.keys())
                else:
                    device_list = [device] if device in vendor.devices else []

                for d in device_list:
                    device_obj = vendor.devices[d]

                    # Get register list for this device
                    if hasattr(device_obj, 'registers'):
                        if register is None or register == '*':
                            register_list = list(device_obj.registers.keys())
                        else:
                            register_list = [register] if register in device_obj.registers else []

                        for r in register_list:
                            reg_obj = device_obj.registers[r]
                            if isinstance(reg_obj, list) and len(reg_obj) > 0:
                                reg_obj = reg_obj[0]

                            # Get field list for this register
                            if hasattr(reg_obj, 'fields'):
                                if field is None or field == '*':
                                    field_list = list(reg_obj.fields.keys())
                                else:
                                    field_list = [field] if field in reg_obj.fields else []

                                for f in field_list:
                                    ret.append(f'{v}.{d}.{r}.{f}')
        else:
            # Fallback to original method if platform not available
            if vid is None or vid == '*':
                vid_list = list(self.cs.Cfg.REGISTERS.keys())
            else:
                vid_list = [vid]

            for v in vid_list:
                if v in self.cs.Cfg.REGISTERS:
                    if device is None or device == '*':
                        dev_list = list(self.cs.Cfg.REGISTERS[v].keys())
                    else:
                        dev_list = [device]

                    for d in dev_list:
                        if d in self.cs.Cfg.REGISTERS[v]:
                            if register is None or register == '*':
                                reg_list = list(self.cs.Cfg.REGISTERS[v][d].keys())
                            else:
                                reg_list = [register]

                            for r in reg_list:
                                if r in self.cs.Cfg.REGISTERS[v][d]:
                                    reg_obj = self.cs.Cfg.REGISTERS[v][d][r][0]
                                    if field is None or field == '*':
                                        field_list = list(reg_obj.fields.keys())
                                    else:
                                        if field in reg_obj.fields:
                                            field_list = [field]
                                        else:
                                            field_list = []

                                    for f in field_list:
                                        ret.append(f'{v}.{d}.{r}.{f}')
        return ret

    def has_all_fields(self, reg_name: str, field_list: List[str]) -> bool:
        """Checks if the register as all fields specified in list"""
        ret = True
        for field in field_list:
            ret = ret and self.has_field(reg_name, field)
            if not ret:
                break
        return ret


class BaseConfigRegisterHelper(BaseConfigHelper):
    def __init__(self, cfg_obj):
        super(BaseConfigRegisterHelper, self).__init__(cfg_obj)
        self.name = cfg_obj['name']
        self.instance = cfg_obj['instance'] if 'instance' in cfg_obj else None
        self.value = None
        self.desc = cfg_obj['desc']
        if 'default' in cfg_obj:
            self.default = cfg_obj['default']
        else:
            self.default = None
        self.fields = cfg_obj['FIELDS']

    def is_enabled(self) -> bool:
        """Check if the register is enabled"""
        return True

    def read(self) -> int:
        """Read the object"""
        raise NotImplementedError()

    def write(self, value: int):
        """Write the object"""
        raise NotImplementedError()

    def print(self) -> None:
        self.logger.log(str(self))

    def __str__(self) -> str:
        return f'{self.name}: {self.value}'

    def get_instance(self) -> Any:
        return self.instance

    def set_value(self, value: int) -> None:
        self.value = value

    def set_field(self, field_name: str, field_value: int, preserve_field_position: Optional[bool] = False) -> int:
        field_name = field_name.upper()
        field_attrs = self.fields[field_name]
        bit = field_attrs['bit']
        size = field_attrs['size']
        self.value = set_bits(bit, size, self.value, field_value, preserve_field_position)
        return self.value

    def get_field(
        self, field_name: str, preserve_field_position: Optional[bool] = False
    ) -> int:
        field_name = field_name.upper()
        if self.value is None:
            self.read()
        field_attrs = self.fields[field_name]
        field_bit = field_attrs['bit']
        field_size = field_attrs['size']
        return get_bits(self.value, field_bit, field_size, preserve_field_position)

    def has_field(self, field_name: str) -> bool:
        field_name = field_name.upper()
        return self.fields.get(field_name, None) is not None

    def has_all_fields(self, field_names: List[str]) -> bool:
        return all(self.has_field(name) for name in field_names)

    def get_mask(self) -> int:
        mask = make_mask(self.size * 8)
        return mask

    def get_field_mask(
        self, reg_field: str, preserve_field_position: Optional[bool] = False
    ) -> int:
        reg_field = reg_field.upper()
        field_attrs = self.fields[reg_field]
        mask_start = 0
        size = field_attrs['size']
        if preserve_field_position:
            mask_start = field_attrs['bit']
        mask = make_mask(size, mask_start)
        return mask

    def write_field(
        self, field_name: str, field_value: int, update_value: bool = False, preserve_field_position: Optional[bool] = False
    ) -> None:
        if update_value or self.value is None:
            if self.value is None:
                self.logger.log_debug(f'Value is None for {self.name}. Reading value')
            self.read()
        new_value = self.set_field(field_name, field_value, preserve_field_position)
        self.write(new_value)

    def read_field(
        self, field_name: str, preserve_field_position: Optional[bool] = False
    ) -> int:
        self.read()
        return self.get_field(field_name, preserve_field_position)

    def _register_fields_str(self, verbose: bool = False) -> str:
        reg_fields_str = ''
        if self.fields:
            reg_fields_str += '\n'
            # sort fields by their bit position in the register
            sorted_fields = sorted(
                self.fields.items(), key=lambda field: field[1]['bit']
            )
            for f in sorted_fields:
                field_attrs = f[1]
                field_bit = field_attrs['bit']
                field_size = field_attrs['size']
                field_mask = 0
                for _ in range(field_size):
                    field_mask = (field_mask << 1) | 1
                field_desc = (
                    (' << ' + field_attrs['desc'] + ' ')
                    if (field_attrs['desc'] != '')
                    else ''
                )
                field_default = (
                    f'(default: {field_attrs["default"]})'
                    if 'default' in field_attrs and verbose
                    else ''
                )
                field_access = (
                    f'(access: {field_attrs["access"]})'
                    if 'access' in field_attrs and verbose
                    else ''
                )
                if self.value is not None:
                    field_value = (self.value >> field_bit) & field_mask
                    reg_fields_str += f'    [{field_bit:02d}] {f[0]:16} = {field_value:X}{field_access}{field_default}{field_desc}\n'

        if '' != reg_fields_str:
            reg_fields_str = reg_fields_str[:-1]
        return reg_fields_str


class ObjList(list):
    def __init__(self, iterable: List[BaseConfigRegisterHelper] = []):
        super().__init__(iterable)

    def read(self) -> List[int]:
        ret = []
        for inst in self:
            try:
                ret.append(inst.read())
            except CSReadError as err:
                logger().log_debug(f'Error reading instance: {err}')
        return ret

    def read_and_print(self) -> List[int]:
        ret_list = self.read()
        self.print()
        return ret_list

    def read_and_verbose_print(self) -> List[int]:
        ret_list = self.read()
        if logger().VERBOSE:
            self.print()
        return ret_list

    def read_and_hal_print(self) -> List[int]:
        ret_list = self.read()
        if logger().HAL:
            self.print()
        return ret_list

    def read_field(
        self, field: str, preserve_field_position: Optional[bool] = False
    ) -> List[int]:
        ret = []
        for inst in self:
            ret.append(inst.read_field(field, preserve_field_position))
        return ret

    def get_field(
        self, field: str, preserve_field_position: Optional[bool] = False
    ) -> List[int]:
        ret = []
        for inst in self:
            ret.append(inst.get_field(field, preserve_field_position))
        return ret

    def write(self, value: int) -> None:
        for inst in self:
            inst.write(value)

    def write_field(self, field: str, value: int) -> None:
        for inst in self:
            inst.write_field(field, value)

    def print(self) -> None:
        for inst in self:
            logger().log(inst)

    def is_all_value(self, value: int, mask: Optional[int] = None) -> bool:
        if mask is None:
            return all(inst.value == value for inst in self)
        return all((inst.value & mask) == value for inst in self)

    def is_any_value(self, value: int, mask: Optional[int] = None) -> bool:
        if mask is None:
            return any(inst.value == value for inst in self)
        return any((inst.value & mask) == value for inst in self)

    def get_field_value_if_equivalent(self, field: str, preserve_field_position: bool = False) -> Optional[int]:
        """Get field value if all instances have the same value for that field"""
        if len(self) == 0:
            return None
        field_value = self[0].get_field(field, preserve_field_position)
        if any(inst.get_field(field, preserve_field_position) != field_value for inst in self[1:]):
            return None
        return field_value

    def is_all_field_value(
        self, value: int, field: str, preserve_field_position: bool = False
    ) -> bool:
        return all(
            inst.get_field(field, preserve_field_position) == value for inst in self
        )

    def is_any_field_value(
        self, value: int, field: str, preserve_field_position: bool = False
    ) -> bool:
        return any(
            inst.get_field(field, preserve_field_position) == value for inst in self
        )

    def filter_by_instance(self, instance: Any) -> 'ObjList':
        if instance is None:
            return self
        return ObjList([inst for inst in self if inst.get_instance() == instance])

    def all_has_field(self, field: str) -> bool:
        return all(inst.has_field(field) for inst in self)

    def filter_with_field(self, field: str) -> 'ObjList':
        return ObjList([inst for inst in self if inst.has_field(field)])
    
    def filter_with_fields(self, fields: List[str]) -> 'ObjList':
        return ObjList([inst for inst in self if inst.has_all_fields(fields)])

    def filter_enabled(self) -> 'ObjList':
        return ObjList([inst for inst in self if inst.is_enabled()])


class RegData(object):
    def __init__(self, value, instance):
        self.__value = value
        self.__instance = instance

    @property
    def value(self):
        return self.__value

    @property
    def instance(self):
        return self.__instance

    @value.setter
    def newvalue(self, value):
        self.__value = value


class NullRegister:
    """
    Null object pattern for register instances that are not found.

    This class provides a safe alternative to returning None when a register
    instance cannot be found, preventing AttributeError exceptions.
    """

    def __init__(self, name: str, instance: Any) -> None:
        """
        Initialize the null register object.

        Args:
            name: Name of the register that was not found
            instance: Instance identifier that was requested
        """
        self.name = name
        self.instance = instance
        self.value = None

    def get_instance(self) -> Any:
        """Return the instance identifier."""
        return self.instance

    def read(self) -> int:
        """Null implementation of read operation."""
        logger().log_warning(f'Attempted to read null register {self.name}')
        return 0

    def write(self, value: int) -> None:
        """Null implementation of write operation."""
        logger().log_warning(f'Attempted to write to null register {self.name}')

    def has_field(self, field_name: str) -> bool:
        """Null implementation - no fields available."""
        return False

    def get_field(self, field_name: str,
                 preserve_field_position: bool = False) -> int:
        """Null implementation of get_field."""
        field_name = field_name.upper()
        logger().log_warning(f'Attempted to get field {field_name} '
                           f'from null register {self.name}')
        return 0

    def read_field(self, field_name: str, preserve_field_position: bool = False) -> int:
        return self.get_field(field_name, preserve_field_position)
