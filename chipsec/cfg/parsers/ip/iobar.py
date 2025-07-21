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

"""
I/O BAR IP Configuration Helper

Provides I/O BAR-specific configuration management functionality for
I/O base address registers.
"""

from typing import Dict, Any, Optional, Union, TYPE_CHECKING

from chipsec.cfg.parsers.ip.generic import GenericConfig, GenericConfigError
from chipsec.library.exceptions import IOBarConfigError

if TYPE_CHECKING:
    from chipsec.cfg.parsers.ip.pci_device import PCIObj



class IOObj:
    """
    I/O object representing an I/O port region.

    Contains base address, size, and associated PCI instance information.
    """

    def __init__(self, instance: 'PCIObj'):
        """
        Initialize I/O object.

        Args:
            instance: Associated PCI object instance
        """
        self.base: Optional[int] = None
        self.size: int = 0
        self.instance = instance

    def set_base_and_size(self, base: Optional[int], size: int) -> None:
        """
        Set base address and size for the I/O region.

        Args:
            base: Base address (can be None)
            size: Size of the I/O region

        Raises:
            IOBarConfigError: If parameters are invalid
        """
        try:
            if base is not None and not isinstance(base, int):
                raise IOBarConfigError(
                    "Base address must be an integer or None")
            if not isinstance(size, int) or size < 0:
                raise IOBarConfigError(
                    "Size must be a non-negative integer")

            self.base = base
            self.size = size
        except Exception as e:
            if isinstance(e, IOBarConfigError):
                raise
            raise IOBarConfigError(
                f"Error setting I/O base and size: {str(e)}") from e

    def is_valid(self) -> bool:
        """
        Check if I/O object is valid.

        Returns:
            True if I/O object has valid configuration
        """
        return (self.base is not None and
                isinstance(self.size, int) and
                self.size >= 0 and
                self.instance is not None)

    def __str__(self) -> str:
        """Return human-readable string representation."""
        basestr = f'0x{self.base:X}' if self.base else 'None'
        return (f'instance: {self.instance}, base: {basestr}, '
                f'size: 0x{self.size:X}')

    def __repr__(self) -> str:
        """Return detailed string representation."""
        return (f"IOObj(base={self.base}, size={self.size}, "
                f"instance={self.instance})")

    def __eq__(self, other) -> bool:
        """
        Check equality with another I/O object.

        Args:
            other: Object to compare with

        Returns:
            True if objects are equal, False otherwise
        """
        if not isinstance(other, IOObj):
            return False
        return (self.base == other.base and
                self.size == other.size and
                self.instance == other.instance)

    def __hash__(self) -> int:
        """
        Generate a hash value for the IOObj instance.

        This allows IOObj instances to be used as dictionary keys.

        Returns:
            Hash value based on base, size, and instance
        """
        # Use instance hash if it implements __hash__, otherwise use id()
        instance_hash = hash(self.instance) \
            if hasattr(self.instance, '__hash__') else id(self.instance)
        return hash((self.base, self.size, instance_hash))


class IOBarConfig(GenericConfig):
    """
    I/O BAR configuration helper for I/O base address registers.

    Manages I/O BAR configurations including register mappings, base fields,
    and device instances.
    """

    def __init__(self, cfg_obj: Dict[str, Any]):
        """
        Initialize I/O BAR configuration helper.

        Args:
            cfg_obj: Configuration object containing I/O BAR-specific fields

        Raises:
            IOBarConfigError: If I/O BAR configuration initialization fails
        """
        try:
            super().__init__(cfg_obj)

            # Required fields
            required_fields = ['device', 'register', 'base_field', 'desc']
            missing_fields = [field for field in required_fields
                              if field not in cfg_obj]
            if missing_fields:
                raise IOBarConfigError(
                    f"Missing required I/O BAR fields: {missing_fields}")

            self.device: str = cfg_obj['device']
            self.register: str = cfg_obj['register']
            self.base_field: str = cfg_obj['base_field']
            self.desc: str = cfg_obj['desc']

            # Optional fields
            self.fixed_address: Optional[Union[int, str]] = cfg_obj.get(
                'fixed_address')
            self.mask: Optional[Union[int, str]] = cfg_obj.get('mask')
            self.offset: Optional[Union[int, str]] = cfg_obj.get('offset')
            self.size: Optional[Union[int, str]] = cfg_obj.get('size')
            self.enable_field: Optional[str] = cfg_obj.get('enable_field')

            # Initialize instances
            self.instances: Dict[Any, IOObj] = {}
            if 'ids' in cfg_obj:
                for key in cfg_obj['ids']:
                    self.add_obj(key)

        except Exception as e:
            if isinstance(e, (IOBarConfigError, GenericConfigError)):
                raise
            raise IOBarConfigError(
                f"Error initializing I/O BAR configuration: {str(e)}") from e

    def add_obj(self, key) -> None:
        """
        Add a new I/O object instance.

        Args:
            key: Key identifier for the I/O instance

        Raises:
            IOBarConfigError: If I/O object creation fails
        """
        try:
            self.instances[key] = IOObj(key)
        except Exception as e:
            raise IOBarConfigError(
                f"Error adding I/O object: {str(e)}") from e

    def remove_instance(self, key) -> bool:
        """
        Remove an I/O instance by key.

        Args:
            key: Key identifier for the instance to remove

        Returns:
            True if instance was removed, False if not found
        """
        if key in self.instances:
            del self.instances[key]
            return True
        return False

    def update_base_address(self, base: Optional[int], instance) -> None:
        """
        Update base address for a specific instance.

        Args:
            base: New base address
            instance: Instance identifier

        Raises:
            IOBarConfigError: If instance not found or update fails
        """
        try:
            if instance not in self.instances:
                raise IOBarConfigError(f"Instance {instance} not found")
            self.instances[instance].base = base
        except Exception as e:
            if isinstance(e, IOBarConfigError):
                raise
            raise IOBarConfigError(
                f"Error updating base address: {str(e)}") from e

    def get_base(self, instance):
        """
        Get base address and size for a specific instance.

        Args:
            instance: Instance identifier

        Returns:
            Tuple of (base_address, size) or (None, 0) if not found
        """
        if instance in self.instances:
            return self.instances[instance].base, self.size
        else:
            return (None, 0)

    def get_instance_count(self) -> int:
        """Get the total number of I/O instances."""
        return len(self.instances)

    def validate_iobar_config(self) -> bool:
        """
        Validate I/O BAR-specific configuration.

        Returns:
            True if I/O BAR configuration is valid, False otherwise
        """
        try:
            # Call parent validation first
            if not self.validate_config():
                return False

            # Validate required fields
            required_attrs = ['device', 'register', 'base_field', 'desc']
            for attr in required_attrs:
                value = getattr(self, attr, None)
                if not value or not isinstance(value, str):
                    return False

            # Validate all I/O instances
            for inst in self.instances.values():
                if not inst.is_valid():
                    return False

            return True
        except Exception:
            return False

    def get_iobar_summary(self) -> Dict[str, Any]:
        """
        Get summary of I/O BAR configuration.

        Returns:
            Dictionary with I/O BAR configuration summary
        """
        try:
            return {
                'name': self.name,
                'device': self.device,
                'register': self.register,
                'base_field': self.base_field,
                'size': self.size,
                'total_instances': len(self.instances),
                'is_valid': self.validate_iobar_config(),
                'config_items': len(self.config)
            }
        except Exception:
            return {
                'name': getattr(self, 'name', 'Unknown'),
                'device': getattr(self, 'device', None),
                'register': getattr(self, 'register', None),
                'base_field': getattr(self, 'base_field', None),
                'size': getattr(self, 'size', None),
                'total_instances': 0,
                'is_valid': False,
                'config_items': 0
            }

    def __str__(self) -> str:
        ret = f'name: {self.name}, device: {self.device}'
        ret += f', register:{self.register}, base_field:{self.base_field}'
        ret += f', size:{self.size}'
        if self.enable_field:
            ret += f', enable_field:{self.enable_field}'
        ret += f', config: {self.config}'
        if self.fixed_address:
            ret += f', fixed_address:{self.fixed_address}'
        ret += f', desc:{self.desc}'
        ret += ', instances: ['
        ret += ' '.join(f'{{{str(inst)}}}' for (_, inst) in self.instances.items())
        ret += ']'
        return ret
