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
MMIO BAR IP Configuration Helper

Provides MMIO BAR-specific configuration management functionality for
memory-mapped I/O base address registers.
"""

from typing import Optional, TYPE_CHECKING

from chipsec.cfg.parsers.ip.generic import GenericConfig, GenericConfigError
from chipsec.cfg.parsers.ip.platform import RegisterList
from chipsec.library.exceptions import MMIOBarConfigError

if TYPE_CHECKING:
    from chipsec.cfg.parsers.ip.pci_device import PCIObj

class MMIOObj:
    """
    MMIO object representing a memory-mapped I/O region.

    Contains base address, size, and associated PCI instance information.
    """

    def __init__(self, instance: 'PCIObj'):
        """
        Initialize MMIO object.

        Args:
            instance: Associated PCI object instance
        """
        self.base: Optional[int] = None
        self.size: int = 0
        self.instance = instance

    def set_base_and_size(self, base: Optional[int], size: int) -> None:
        """
        Set base address and size for the MMIO region.

        Args:
            base: Base address (can be None)
            size: Size of the MMIO region

        Raises:
            MMIOBarConfigError: If parameters are invalid
        """
        try:
            if base is not None and not isinstance(base, int):
                raise MMIOBarConfigError(
                    "Base address must be an integer or None")
            if not isinstance(size, int) or size < 0:
                raise MMIOBarConfigError(
                    "Size must be a non-negative integer")

            self.base = base
            self.size = size
        except MMIOBarConfigError:
            raise
        except Exception as e:
            raise MMIOBarConfigError(
                f"Error setting MMIO base and size: {str(e)}") from e

    def is_valid(self) -> bool:
        """
        Check if MMIO object is valid.

        Returns:
            True if MMIO object has valid configuration
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
        return (f"MMIOObj(base={self.base}, size={self.size}, "
                f"instance={self.instance})")

    def __eq__(self, other) -> bool:
        """
        Check equality with another MMIO object.

        Args:
            other: Object to compare with

        Returns:
            True if objects are equal, False otherwise
        """
        if not isinstance(other, MMIOObj):
            return False
        return (self.base == other.base and
                self.size == other.size and
                self.instance == other.instance)

    def __hash__(self) -> int:
        """
        Generate a hash value for the MMIOObj instance.

        This allows MMIOObj instances to be used as dictionary keys.

        Returns:
            Hash value based on base, size, and instance
        """
        # Use instance hash if it implements __hash__, otherwise use id()
        instance_hash = hash(self.instance) \
            if hasattr(self.instance, '__hash__') else id(self.instance)
        return hash((self.base, self.size, instance_hash))


class MMIOBarConfig(GenericConfig, RegisterList):
    """
    MMIO BAR configuration helper for memory-mapped I/O base address registers.

    Manages MMIO BAR configurations including register mappings, base fields,
    size information, and device instances.
    """

    def __init__(self, cfg_obj):
        """
        Initialize MMIO BAR configuration helper.

        Args:
            cfg_obj: Configuration object containing MMIO BAR-specific fields

        Raises:
            MMIOBarConfigError: If MMIO BAR configuration initialization fails
        """
        try:
            GenericConfig.__init__(self, cfg_obj)
            RegisterList.__init__(self)

            # Required fields
            if 'register' not in cfg_obj or 'base_field' not in cfg_obj:
                raise MMIOBarConfigError(
                    "Missing required fields: register and/or base_field")

            # Device field (can be 'device' or 'component')
            self.device = (cfg_obj.get('device') or
                           cfg_obj.get('component'))

            # Core configuration
            self.register = cfg_obj['register']
            self.base_field = cfg_obj['base_field']
            self.size = cfg_obj.get('size')
            self.desc = cfg_obj.get('desc', self.name)
            self.reg_align = cfg_obj.get('reg_align')
            self.registerh = cfg_obj.get('registerh')
            self.reg_alignh = cfg_obj.get('reg_alignh')
            self.baseh_field = cfg_obj.get('baseh_field')
            self.registertype = cfg_obj.get('registertype')
            self.offset = cfg_obj.get('offset', 0)
            self.mmio_base = cfg_obj.get('mmio_base')
            self.mmio_align = cfg_obj.get('mmio_align')
            self.limit_field = cfg_obj.get('limit_field')
            self.limit_register = cfg_obj.get('limit_register')
            self.limit_align = cfg_obj.get('limit_align')
            self.fixed_address = cfg_obj.get('fixed_address')
            self.enable_field = cfg_obj.get('enable_field')
            self.enable_bit = cfg_obj.get('enable_bit')
            self.valid = cfg_obj.get('valid')

            # Initialize instances
            self.instances = {}
            if 'ids' in cfg_obj:
                for key in cfg_obj['ids']:
                    self.add_obj(key)

        except MMIOBarConfigError:
            raise
        except Exception as e:
            raise MMIOBarConfigError(
                f"Error initializing MMIO BAR configuration: {str(e)}") from e

    def add_obj(self, key):
        """
        Add a new MMIO object instance.

        Args:
            key: Key identifier for the MMIO instance

        Raises:
            MMIOBarConfigError: If MMIO object creation fails
        """
        try:
            self.instances[key] = MMIOObj(key)
        except Exception as e:
            raise MMIOBarConfigError(
                f"Error adding MMIO object: {str(e)}") from e

    def remove_instance(self, key) -> bool:
        """
        Remove an MMIO instance by key.

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
            MMIOBarConfigError: If instance not found or update fails
        """
        if instance is None:
            for inst in self.instances:
                self.instances[inst].base = base
        else:
            try:
                if instance not in self.instances:
                    raise MMIOBarConfigError(f"Instance {instance} not found")
                self.instances[instance].base = base
            except MMIOBarConfigError:
                raise
            except Exception as e:
                raise MMIOBarConfigError(
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
        """Get the total number of MMIO instances."""
        return len(self.instances)

    def validate_mmio_config(self) -> bool:
        """
        Validate MMIO BAR-specific configuration.

        Returns:
            True if MMIO BAR configuration is valid, False otherwise
        """
        try:
            # Call parent validation first
            if not self.validate_config():
                return False

            # Validate required fields
            if not self.register or not self.base_field:
                return False

            # Validate all MMIO instances
            for inst in self.instances.values():
                if not inst.is_valid():
                    return False

            return True
        except Exception:
            return False

    def get_mmio_summary(self):
        """
        Get summary of MMIO BAR configuration.

        Returns:
            Dictionary with MMIO BAR configuration summary
        """
        try:
            return {
                'name': self.name,
                'device': self.device,
                'register': self.register,
                'base_field': self.base_field,
                'size': self.size,
                'total_instances': len(self.instances),
                'is_valid': self.validate_mmio_config(),
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
        """Return human-readable string representation."""
        ret = f'name: {self.name}, device: {self.device}'
        ret += f', register: {self.register}, base_field: {self.base_field}'
        ret += f', size: {self.size}'
        ret += f', config: {len(self.config)} items'

        # Add optional fields if present
        optional_fields = [
            ('reg_align', self.reg_align),
            ('registerh', self.registerh),
            ('reg_alignh', self.reg_alignh),
            ('baseh_field', self.baseh_field),
            ('registertype', self.registertype),
            ('mmio_base', self.mmio_base),
            ('mmio_align', self.mmio_align),
            ('limit_field', self.limit_field),
            ('limit_register', self.limit_register),
            ('limit_align', self.limit_align),
            ('fixed_address', self.fixed_address),
            ('enable_field', self.enable_field),
            ('valid', self.valid)
        ]

        for field_name, field_value in optional_fields:
            if field_value:
                ret += f', {field_name}: {field_value}'

        ret += f', desc: {self.desc}'
        ret += ', instances: ['
        ret += ' '.join(f'{{{str(inst)}}}'
                       for (_, inst) in self.instances.items())
        ret += ']'
        return ret

    def __repr__(self) -> str:
        """Return detailed string representation."""
        return (f"MMIOBarConfig(name='{self.name}', device='{self.device}', "
                f"register='{self.register}', instances={len(self.instances)}, "
                f"config_count={len(self.config)})")
