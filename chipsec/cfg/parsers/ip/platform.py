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

"""
Platform configuration parser and hierarchy management.

This module provides classes for managing platform configurations in a hierarchical structure:
Platform -> Vendor -> IP -> Bar -> Register. It supports pattern matching, scoping,
and register access across the configuration hierarchy.
"""

from typing import List, Union, Any
from re import match

from chipsec.library.exceptions import (
    PlatformConfigError, RegisterNotFoundError, ScopeNotFoundError, BARNotFoundError
)
from chipsec.library.register import ObjList
from chipsec.library.logger import logger

class Recursable:
    """
    Base class for objects that support recursive navigation and pattern matching.

    This class provides the foundation for hierarchical traversal of platform configurations,
    supporting wildcard matching and recursive object discovery.
    """

    def _get_next_level_list(self) -> List[str]:
        """
        Get list of available keys at the next level.

        Returns:
            List of string keys for the next hierarchy level

        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError('_get_next_level_list() not implemented')

    def get_next_levels(self, key: str) -> List['Recursable']:
        """
        Get objects matching the given key pattern.

        Args:
            key: Key pattern, supports wildcards (*)

        Returns:
            List of matching objects at the next level
        """
        key = key.replace('*', '.*')
        next_options = []

        # Determine search scope
        if '*' not in key and key in self._get_next_level_list():
            next_options_list = [key]
        else:
            next_options_list = self._get_next_level_list()

        # Find matching options
        for option in next_options_list:
            if match(key, option):
                next_option = self._get_next_level(option)
                if isinstance(next_option, list):
                    next_options.extend(next_option)
                else:
                    next_options.append(next_option)

        return next_options

    def _get_next_level(self, key: str) -> Union['Recursable', List['Recursable']]:
        """
        Get the object(s) at the next level for a specific key.

        Args:
            key: Specific key to retrieve

        Returns:
            Object or list of objects at the next level

        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError("_get_next_level() not implemented")


class RegisterList:
    """
    Container for managing register objects with pattern matching support.

    This class provides functionality to add, retrieve, and search for registers
    using both exact names and wildcard patterns.
    """

    def __init__(self) -> None:
        """Initialize empty register list."""
        self.register_list = {}

    def add_register(self, register_name: str, register_object: Any) -> None:
        """
        Add a register to the list.

        Args:
            register_name: Name of the register
            register_object: Register object to add
        """
        self.register_list[register_name] = register_object
        self.__setattr__(register_name, register_object)

    def get_register(self, register_name: str) -> ObjList:
        """
        Get a specific register by name.

        Args:
            register_name: Name of the register to retrieve

        Returns:
            ObjList containing the register

        Raises:
            RegisterNotFoundError: If register not found
        """
        if register_name in self.register_list:
            return ObjList(self.__getattribute__(register_name))
        else:
            raise RegisterNotFoundError(f'Invalid register name: {register_name}')

    def get_register_matches(self, register_name: str) -> ObjList:
        """
        Get registers matching a pattern.

        Args:
            register_name: Register name pattern (supports wildcards)

        Returns:
            ObjList containing matching registers

        Raises:
            RegisterNotFoundError: If no matches found
        """
        registers = ObjList()
        reg_name = register_name.replace('*', '.*')

        for reg in self.register_list:
            if match(reg_name, reg):
                registers.extend(self.get_register(reg))

        if registers:
            return registers
        else:
            raise RegisterNotFoundError(f'Invalid register name: {register_name}')


class Platform(Recursable):
    """
    Top-level platform configuration container.

    This class manages vendors and provides hierarchical access to the entire
    platform configuration structure. It supports complex scope resolution
    and pattern matching across the configuration hierarchy.
    """

    def __init__(self) -> None:
        """Initialize empty platform."""
        super().__init__()
        self.vendor_list = []

    def add_vendor(self, vendor: 'Vendor') -> None:
        """
        Add a vendor to the platform.

        Args:
            vendor: Vendor object to add

        Raises:
            PlatformConfigError: If vendor object is invalid
        """
        if not isinstance(vendor, Vendor):
            raise PlatformConfigError(f'Invalid vendor object: {vendor}')

        self.vendor_list.append(vendor.name)
        self.__setattr__(f'_{vendor.name}', vendor)

    def get_vendor(self, vendor_name: str) -> 'Vendor':
        """
        Get a vendor by name.

        Args:
            vendor_name: Name of the vendor

        Returns:
            Vendor object

        Raises:
            PlatformConfigError: If vendor not found
        """
        if vendor_name in self.vendor_list:
            return self.__getattribute__(f'_{vendor_name}')
        else:
            raise PlatformConfigError(f'Invalid vendor name: {vendor_name}')

    def remove_vendor(self, vendor: 'Vendor') -> None:
        """
        Remove a vendor from the platform.

        Args:
            vendor: Vendor object to remove

        Raises:
            PlatformConfigError: If vendor object is invalid
        """
        if not isinstance(vendor, Vendor) or vendor.name not in self.vendor_list:
            raise PlatformConfigError(f'Invalid vendor object: {vendor}')

        self.vendor_list.remove(vendor.name)
        self.__delattr__(f'_{vendor.name}')

    def _get_next_level_list(self) -> List[str]:
        """Get list of vendor names."""
        return self.vendor_list

    def _get_next_level(self, name: str) -> 'Vendor':
        """Get vendor by name."""
        return self.get_vendor(name)

    def get_obj_from_fullname(self, full_name: str) -> Any:
        """
        Get object from full dotted name.

        Args:
            full_name: Dotted name path (e.g., 'vendor.ip.bar.register')

        Returns:
            Object at the specified path
        """
        return self.get_obj_from_scope(full_name.split('.'))

    def get_obj_from_scope(self, scope: List[str]) -> Any:
        """
        Get object from scope list.

        Args:
            scope: List of scope components

        Returns:
            Object at the specified scope

        Raises:
            ScopeNotFoundError: If scope contains wildcards or is invalid
        """
        logger().log_debug(f'Getting obj from scope: {scope}')
        if any('*' in s for s in scope):
            raise ScopeNotFoundError(f'Invalid scope: {scope}. No wildcards allowed for this function.')
        return Platform._get_obj_from_split_scope(self, scope)

    @staticmethod
    def _get_obj_from_split_scope(obj: Any, scope: List[str]) -> Any:
        """
        Recursively traverse scope to find object.

        Args:
            obj: Current object in traversal
            scope: Remaining scope components

        Returns:
            Object at the end of scope traversal

        Raises:
            ScopeNotFoundError: If scope cannot be resolved
        """
        if not scope:
            raise ScopeNotFoundError(f'Scope {scope} on obj {obj} was not found')

        root_scope = scope.pop(0)
        next_level = obj._get_next_level(root_scope)

        if len(scope) == 0:
            return next_level
        return Platform._get_obj_from_split_scope(next_level, scope)

    def get_matches_from_fullname(self, full_name: str) -> List[Any]:
        """
        Get matching objects from full dotted name with wildcards.

        Args:
            full_name: Dotted name path with wildcards (e.g., 'vendor.*.register')

        Returns:
            List of matching objects
        """
        return self.get_matches_from_scope(full_name.split('.'))

    def get_matches_from_scope(self, scope: List[str]) -> List[Any]:
        """
        Get matching objects from scope list with wildcards.

        Args:
            scope: List of scope components with wildcards

        Returns:
            List of matching objects
        """
        logger().log_debug(f'Getting matches from scope: {scope}')
        return Platform._get_matches_from_split_scope([self], scope)

    @staticmethod
    def _get_matches_from_split_scope(objs: List[Any], scope: List[str]) -> List[Any]:
        """
        Recursively find matching objects in scope.

        Args:
            objs: Current objects in traversal
            scope: Remaining scope components

        Returns:
            List of matching objects

        Raises:
            ScopeNotFoundError: If scope cannot be resolved
        """
        if not scope:
            raise ScopeNotFoundError(f'Scope {scope} on objs: {objs} was not found')

        root_scope = scope.pop(0)
        next_level_list = []
        for obj in objs:
            next_level_list.extend(obj.get_next_levels(root_scope))

        if len(scope) == 0:
            return next_level_list
        return Platform._get_matches_from_split_scope(next_level_list, scope)

    def get_register_from_fullname(self, full_name: str) -> ObjList:
        """
        Get register from full dotted name.

        Args:
            full_name: Dotted name path to register

        Returns:
            Register object list
        """
        return self.get_register_from_scope(full_name.split('.'))

    def get_register_from_scope(self, scope: List[str]) -> ObjList:
        """
        Get register from scope list.

        Args:
            scope: List of scope components to register

        Returns:
            Register object list

        Raises:
            ScopeNotFoundError: If scope contains wildcards or is invalid
        """
        logger().log_debug(f'Getting register from scope: {scope}')
        if any('*' in s for s in scope):
            raise ScopeNotFoundError(f'Invalid scope: {scope}. No wildcards allowed for this function.')
        return Platform._get_register_from_split_scope(self, scope)

    @staticmethod
    def _get_register_from_split_scope(obj: Any, scope: List[str]) -> ObjList:
        """
        Recursively traverse scope to find register.

        Args:
            obj: Current object in traversal
            scope: Remaining scope components

        Returns:
            Register object list

        Raises:
            ScopeNotFoundError: If scope cannot be resolved
        """
        if not scope:
            raise ScopeNotFoundError(f'Scope {scope} on obj {obj} was not found')

        root_scope = scope.pop(0)
        if len(scope) == 0:
            return obj.get_register(root_scope)
        else:
            next_level = obj._get_next_level(root_scope)

        return Platform._get_register_from_split_scope(next_level, scope)

    def get_register_matches_from_fullname(self, full_name: str) -> ObjList:
        """
        Get matching registers from full dotted name with wildcards.

        Args:
            full_name: Dotted name path with wildcards

        Returns:
            List of matching register objects
        """
        return self.get_register_matches_from_scope(full_name.split('.'))

    def get_register_matches_from_scope(self, scope: List[str]) -> ObjList:
        """
        Get matching registers from scope list with wildcards.

        Args:
            scope: List of scope components with wildcards

        Returns:
            List of matching register objects
        """
        logger().log_debug(f'Getting registers from matchscope: {scope}')
        objects = Platform._get_register_matches_from_split_scope([self], scope)
        return ObjList(objects)

    @staticmethod
    def _get_register_matches_from_split_scope(objs: List[Any], scope: List[str]) -> List[Any]:
        """
        Recursively find matching registers in scope.

        Args:
            objs: Current objects in traversal
            scope: Remaining scope components

        Returns:
            List of matching register objects

        Raises:
            ScopeNotFoundError: If scope cannot be resolved
        """
        if not scope:
            raise ScopeNotFoundError(f'Scope {scope} on objs: {objs} was not found')

        root_scope = scope.pop(0)
        next_level_list = []
        if len(scope) == 0:
            for obj in objs:
                next_level_list.extend(obj.get_register_matches(root_scope))
            return next_level_list
        else:
            for obj in objs:
                next_level_list.extend(obj.get_next_levels(root_scope))

        return Platform._get_register_matches_from_split_scope(next_level_list, scope)


class Vendor(Recursable):
    """
    Vendor configuration container.

    This class manages IP configurations for a specific vendor and provides
    hierarchical access to vendor-specific platform components.
    """

    def __init__(self, name: str) -> None:
        """
        Initialize vendor configuration.

        Args:
            name: Name of the vendor
        """
        super().__init__()
        self.ip_list = []
        self.name = name

    def add_ip(self, ip_name: str, obj: Any) -> None:
        """
        Add an IP configuration to the vendor.

        Args:
            ip_name: Name of the IP
            obj: IP configuration object
        """
        ip = IP(ip_name, obj)
        self.ip_list.append(ip.name)
        self.__setattr__(ip.name, ip)

    def get_ip(self, ip_name: str) -> 'IP':
        """
        Get an IP configuration by name.

        Args:
            ip_name: Name of the IP

        Returns:
            IP configuration object

        Raises:
            PlatformConfigError: If IP not found
        """
        if ip_name in self.ip_list:
            return self.__getattribute__(ip_name)
        else:
            raise PlatformConfigError(f'Device: {ip_name} not found in Vendor: {self.name}')

    def _get_next_level_list(self) -> List[str]:
        """Get list of IP names."""
        return self.ip_list

    def _get_next_level(self, ip_name: str) -> 'IP':
        """Get IP by name."""
        return self.get_ip(ip_name)


class IP(Recursable, RegisterList):
    """
    IP (Intellectual Property) configuration container.

    This class manages BAR configurations and registers for a specific IP block,
    providing hierarchical access to IP-specific components.
    """

    def __init__(self, name: str, ipobj: Any) -> None:
        """
        Initialize IP configuration.

        Args:
            name: Name of the IP
            ipobj: IP configuration object
        """
        super().__init__()
        RegisterList.__init__(self)
        self.bar_list = []
        self.name = name
        self.obj = ipobj

    def add_bar(self, bar_name: str, barobj: Any) -> None:
        """
        Add a BAR configuration to the IP.

        Args:
            bar_name: Name of the BAR
            barobj: BAR configuration object
        """
        bar = Bar(bar_name, barobj)
        self.bar_list.append(bar.name)
        self.__setattr__(f'{bar.name}_', bar)

    def get_bar(self, bar_name: str) -> 'Bar':
        """
        Get a BAR configuration by name.

        Args:
            bar_name: Name of the BAR

        Returns:
            BAR configuration object

        Raises:
            BARNotFoundError: If BAR not found
        """
        if bar_name in self.bar_list:
            return self.__getattribute__(f'{bar_name}_')
        else:
            raise BARNotFoundError(f'Bar: {bar_name} not found in IP: {self.name}')

    def _get_next_level_list(self) -> List[str]:
        """Get list of BAR names."""
        return self.bar_list

    def _get_next_level(self, bar_id: str) -> 'Bar':
        """
        Get next level object (BAR) by ID.

        Args:
            bar_id: BAR identifier

        Returns:
            BAR object

        Raises:
            PlatformConfigError: If BAR not found
        """
        if bar_id in self._get_next_level_list():
            return self.get_bar(bar_id)
        else:
            raise PlatformConfigError(f'Next Level: {bar_id} not found in IP: {self.name}')


class Bar(Recursable, RegisterList):
    """
    BAR (Base Address Register) configuration container.

    This class manages registers within a specific BAR and provides
    hierarchical access to BAR-specific registers.
    """

    def __init__(self, name: str, barobj: Any) -> None:
        """
        Initialize BAR configuration.

        Args:
            name: Name of the BAR
            barobj: BAR configuration object
        """
        super().__init__()
        RegisterList.__init__(self)
        self.name = name
        self.obj = barobj

    def _get_next_level_list(self) -> List[str]:
        """Get list of register names."""
        return list(self.register_list.keys())

    def _get_next_level(self, register_id: str) -> ObjList:
        """
        Get next level object (register) by ID.

        Args:
            register_id: Register identifier

        Returns:
            Register object list

        Raises:
            PlatformConfigError: If register not found
        """
        if register_id in self.register_list.keys():
            return self.get_register(register_id)
        else:
            raise PlatformConfigError(f'Register: {register_id} not found in BAR: {self.name}')
