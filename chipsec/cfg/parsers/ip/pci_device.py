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
PCI Device IP Configuration Helper

Provides PCI device-specific configuration management functionality for
PCI-based IP parsers.
"""

from typing import Dict, Any, Optional, List, Union

from chipsec.cfg.parsers.ip.generic import GenericConfig
from chipsec.library.exceptions import PCIConfigError, GenericConfigError

class PCIObj:
    """
    PCI device object representing a single PCI device instance.

    Contains bus, device, function, and revision ID information for a
    PCI device.
    """

    def __init__(self, cfg_obj: Dict[str, Any]):
        """
        Initialize PCI device object.

        Args:
            cfg_obj: Configuration object containing PCI device information

        Raises:
            PCIConfigError: If required PCI configuration is missing
        """
        try:
            required_fields = ['bus', 'dev', 'fun']
            missing_fields = [field for field in required_fields
                              if field not in cfg_obj]
            if missing_fields:
                raise PCIConfigError(
                    f"Missing required PCI fields: {missing_fields}")

            self.bus: Union[int, str] = cfg_obj['bus']
            self.dev: Union[int, str] = cfg_obj['dev']
            self.fun: Union[int, str] = cfg_obj['fun']
            self.rid: Union[int, str] = cfg_obj.get('rid', 0xff)

        except Exception as e:
            if isinstance(e, PCIConfigError):
                raise
            raise PCIConfigError(
                f"Error initializing PCI object: {str(e)}") from e

    def get_bdf_tuple(self) -> tuple:
        """
        Get Bus:Device:Function as a tuple.

        Returns:
            Tuple of (bus, dev, fun)
        """
        return (self.bus, self.dev, self.fun)

    def get_bdf_string(self) -> str:
        """
        Get Bus:Device:Function as a formatted string.

        Returns:
            BDF string in format "bus:dev.fun"
        """
        return f"{self.bus:02x}:{self.dev:02x}.{self.fun}"

    def validate_pci_obj(self) -> bool:
        """
        Validate PCI object configuration.

        Returns:
            True if PCI object is valid, False otherwise
        """
        try:
            # Check that all fields are present and valid
            for field_name, field_value in [('bus', self.bus),
                                            ('dev', self.dev),
                                            ('fun', self.fun),
                                            ('rid', self.rid)]:
                if isinstance(field_value, str):
                    try:
                        int(field_value, 0)
                    except ValueError:
                        return False
                elif not isinstance(field_value, int):
                    return False
            return True
        except Exception:
            return False

    def __str__(self) -> str:
        """Return human-readable string representation."""
        ret = f'bus: {self.bus}, dev: {self.dev}, func: {self.fun}'
        ret += f', rid: {self.rid}'
        return ret

    def __repr__(self) -> str:
        """Return detailed string representation."""
        return (f"PCIObj(bus={self.bus}, dev={self.dev}, "
                f"fun={self.fun}, rid={self.rid})")

    def __eq__(self, other) -> bool:
        """Check equality with another PCI object."""
        if not isinstance(other, PCIObj):
            return False
        return (self.bus == other.bus and self.dev == other.dev and
                self.fun == other.fun and self.rid == other.rid)

    def __hash__(self) -> int:
        """
        Generate a hash value for the PCIObj instance.

        This allows PCIObj instances to be used as dictionary keys.

        Returns:
            Hash value based on bus, device, function, and revision ID
        """
        # Convert fields to integers for consistent hashing
        bus = self._convert_to_int(self.bus)
        dev = self._convert_to_int(self.dev)
        fun = self._convert_to_int(self.fun)
        rid = self._convert_to_int(self.rid)

        return hash((bus, dev, fun, rid))

    def _convert_to_int(self, value: Union[int, str]) -> int:
        """
        Convert a value to integer for hashing purposes.

        Args:
            value: Value to convert (int or str)

        Returns:
            Integer representation of the value
        """
        if isinstance(value, str):
            return int(value, 0)
        return value


class PCIConfig(GenericConfig):
    """
    PCI configuration helper for PCI device-based IP regions.

    Manages PCI device configurations including device IDs, components,
    and multiple device instances.
    """

    def __init__(self, cfg_obj: Dict[str, Any]):
        """
        Initialize PCI configuration helper.

        Args:
            cfg_obj: Configuration object containing PCI-specific fields

        Raises:
            PCIConfigError: If PCI configuration initialization fails
        """
        try:
            # Handle device ID and name
            self.did: Optional[int] = cfg_obj.get('did', None)
            if 'name' not in cfg_obj and self.did is not None:
                cfg_obj['name'] = str(self.did)
                self.__name_updated = False
            elif 'name' in cfg_obj:
                self.__name_updated = True
            super().__init__(cfg_obj)

            self.instances: Dict[int, PCIObj] = {}
            self.component: Optional[str] = cfg_obj.get('component', None)
            self.__instCounter: int = 0

            # Add the initial PCI object
            self.add_obj(cfg_obj)

        except Exception as e:
            if isinstance(e, (PCIConfigError, GenericConfigError)):
                raise
            raise PCIConfigError(
                f"Error initializing PCI configuration: {str(e)}") from e

    def add_obj(self, cfg_obj: Dict[str, Any]) -> int:
        """
        Add a new PCI object instance.

        Args:
            cfg_obj: Configuration object for the PCI device

        Returns:
            Instance counter for the added object

        Raises:
            PCIConfigError: If PCI object creation fails
        """
        try:
            pci_obj = PCIObj(cfg_obj)
            self.instances[self.__instCounter] = pci_obj
            current_counter = self.__instCounter
            self.__instCounter += 1
            return current_counter
        except Exception as e:
            raise PCIConfigError(
                f"Error adding PCI object: {str(e)}") from e

    def remove_instance(self, instance_id: int) -> bool:
        """
        Remove a PCI instance by ID.

        Args:
            instance_id: Instance ID to remove

        Returns:
            True if instance was removed, False if not found
        """
        if instance_id in self.instances:
            del self.instances[instance_id]
            return True
        return False

    def get_rid(self, bus: Union[int, str], dev: Union[int, str],
                fun: Union[int, str]) -> Union[int, str]:
        """
        Get revision ID for a specific Bus:Device:Function.

        Args:
            bus: PCI bus number
            dev: PCI device number
            fun: PCI function number

        Returns:
            Revision ID if found, 0xff otherwise
        """
        rid = 0xff
        for inst in self.instances.values():
            if inst.bus == bus and inst.dev == dev and inst.fun == fun:
                rid = inst.rid
                break
        return rid

    def get_enabled_instances(self) -> List[PCIObj]:
        """
        Get list of enabled PCI instances (those with valid bus numbers).

        Returns:
            List of enabled PCI objects
        """
        enabled = []
        for inst in self.instances.values():
            if inst.bus is not None:
                enabled.append(inst)
        return enabled

    def get_instance_count(self) -> int:
        """Get the total number of PCI instances."""
        return len(self.instances)

    def find_instance_by_bdf(self, bus: Union[int, str],
                             dev: Union[int, str],
                             fun: Union[int, str]) -> Optional[PCIObj]:
        """
        Find PCI instance by Bus:Device:Function.

        Args:
            bus: PCI bus number
            dev: PCI device number
            fun: PCI function number

        Returns:
            PCIObj if found, None otherwise
        """
        for inst in self.instances.values():
            if inst.bus == bus and inst.dev == dev and inst.fun == fun:
                return inst
        return None

    def validate_pci_config(self) -> bool:
        """
        Validate PCI-specific configuration.

        Returns:
            True if PCI configuration is valid, False otherwise
        """
        try:
            # Call parent validation first
            if not self.validate_config():
                return False

            # Validate all PCI instances
            for inst in self.instances.values():
                if not inst.validate_pci_obj():
                    return False

            # Validate component if present
            if self.component is not None and not isinstance(self.component, str):
                return False

            return True
        except Exception:
            return False

    def update_name(self, name: str) -> bool:
        """Update the configuration name if it hasn't been updated before.

        This method allows updating the name only once. Subsequent calls will be ignored
        and logged as debug messages.

            name (str): New name for the configuration. Must be a non-empty string.

        Returns:
            bool: True if the name was successfully updated, False if the name has 
                  already been set previously.

            PCIConfigError: If name is not a string or is empty/whitespace only."""

        if not isinstance(name, str) or not name.strip():
            raise PCIConfigError("IP must be a non-empty string")
        if not self.__name_updated:
            self.name = name
            self.__name_updated = True
            return True
        self.logger.log_debug(f"Name has already been set to {self.name} and cannot be updated to {name}")
        return False

    def get_pci_summary(self) -> Dict[str, Any]:
        """
        Get summary of PCI configuration.

        Returns:
            Dictionary with PCI configuration summary
        """
        try:
            enabled_instances = self.get_enabled_instances()
            return {
                'name': self.name,
                'did': self.did,
                'component': self.component,
                'total_instances': len(self.instances),
                'enabled_instances': len(enabled_instances),
                'is_valid': self.validate_pci_config(),
                'config_items': len(self.config)
            }
        except Exception:
            return {
                'name': getattr(self, 'name', 'Unknown'),
                'did': getattr(self, 'did', None),
                'component': getattr(self, 'component', None),
                'total_instances': 0,
                'enabled_instances': 0,
                'is_valid': False,
                'config_items': 0
            }

    def __str__(self) -> str:
        """Return human-readable string representation."""
        if self.did:
            if isinstance(self.did, int):
                ret = f'name: {self.name}, did: {self.did:04X}'
            else:
                ret = f'name: {self.name}, did: {self.did}'
        else:
            ret = f'name: {self.name}, did: {self.did}'
        ret += f', component: {self.component}'
        ret += f', config: {len(self.config)} items'
        ret += ', instances: ['
        ret += ' '.join(f'{{{str(inst)}}}' for inst in self.instances.values())
        ret += ']'
        return ret

    def __repr__(self) -> str:
        """Return detailed string representation."""
        return (f"PCIConfig(name='{self.name}', did={self.did}, "
                f"component='{self.component}', instances={len(self.instances)}, "
                f"config_count={len(self.config)})")
