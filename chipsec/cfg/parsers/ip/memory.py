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
Memory IP Configuration Helper

Provides memory-specific configuration management functionality for
memory-mapped regions.
"""

from typing import Dict, Any, Union

from chipsec.cfg.parsers.ip.generic import GenericConfig
from chipsec.library.exceptions import MemoryConfigError

class MemoryConfig(GenericConfig):
    """
    Memory configuration helper for memory-mapped IP regions.

    Handles configuration of memory-mapped regions including access
    permissions, address ranges, and size limits.
    """

    def __init__(self, cfg_obj: Dict[str, Any]):
        """
        Initialize memory configuration helper.

        Args:
            cfg_obj: Configuration object containing memory-specific fields

        Raises:
            MemoryConfigError: If required memory configuration is missing
                              or invalid
        """
        try:
            super().__init__(cfg_obj)

            # Required fields for memory configuration
            required_fields = ['access', 'address', 'limit']
            missing_fields = [field for field in required_fields
                              if field not in cfg_obj]
            if missing_fields:
                raise MemoryConfigError(
                    f"Missing required memory configuration fields: "
                    f"{missing_fields}")

            self.access: str = cfg_obj['access']
            self.address: Union[int, str] = cfg_obj['address']
            self.limit: Union[int, str] = cfg_obj['limit']

            # Validate configuration after initialization
            if not self.validate_memory_config():
                raise MemoryConfigError(
                    "Invalid memory configuration detected")

        except Exception as e:
            if isinstance(e, MemoryConfigError):
                raise
            raise MemoryConfigError(
                f"Error initializing memory configuration: {str(e)}") from e

    def validate_memory_config(self) -> bool:
        """
        Validate memory-specific configuration.

        Returns:
            True if memory configuration is valid, False otherwise
        """
        try:
            # Call parent validation first
            if not self.validate_config():
                return False

            # Validate access field
            if not isinstance(self.access, str) or not self.access.strip():
                return False

            # Validate address and limit (can be int or hex string)
            for field_name, field_value in [('address', self.address),
                                            ('limit', self.limit)]:
                if isinstance(field_value, str):
                    # Try to parse as hex if it's a string
                    try:
                        int(field_value, 0)
                    except ValueError:
                        return False
                elif not isinstance(field_value, int):
                    return False

            return True
        except Exception:
            return False

    def get_address_int(self) -> int:
        """
        Get address as integer value.

        Returns:
            Address as integer

        Raises:
            MemoryConfigError: If address cannot be converted to integer
        """
        try:
            if isinstance(self.address, int):
                return self.address
            elif isinstance(self.address, str):
                return int(self.address, 0)
            else:
                raise MemoryConfigError(
                    f"Invalid address type: {type(self.address)}")
        except ValueError as e:
            raise MemoryConfigError(
                f"Cannot convert address to integer: {self.address}") from e

    def get_limit_int(self) -> int:
        """
        Get limit as integer value.

        Returns:
            Limit as integer

        Raises:
            MemoryConfigError: If limit cannot be converted to integer
        """
        try:
            if isinstance(self.limit, int):
                return self.limit
            elif isinstance(self.limit, str):
                return int(self.limit, 0)
            else:
                raise MemoryConfigError(
                    f"Invalid limit type: {type(self.limit)}")
        except ValueError as e:
            raise MemoryConfigError(
                f"Cannot convert limit to integer: {self.limit}") from e

    def get_memory_range(self) -> int:
        """
        Calculate the memory range (limit - address).

        Returns:
            Memory range size as integer

        Raises:
            MemoryConfigError: If range calculation fails
        """
        try:
            address_int = self.get_address_int()
            limit_int = self.get_limit_int()

            if limit_int < address_int:
                raise MemoryConfigError(
                    f"Invalid memory range: limit ({limit_int:x}) < "
                    f"address ({address_int:x})")

            return limit_int - address_int
        except Exception as e:
            if isinstance(e, MemoryConfigError):
                raise
            raise MemoryConfigError(
                f"Error calculating memory range: {str(e)}") from e

    def __str__(self) -> str:
        """Return human-readable string representation."""
        try:
            addr_str = (f"0x{self.get_address_int():x}"
                        if isinstance(self.address, int)
                        else str(self.address))
            limit_str = (f"0x{self.get_limit_int():x}"
                         if isinstance(self.limit, int)
                         else str(self.limit))
            range_size = self.get_memory_range()

            ret = f'name: {self.name}, access: {self.access}'
            ret += f', address: {addr_str}, limit: {limit_str}'
            ret += f', range: 0x{range_size:x}, config: {len(self.config)} items'
            return ret
        except Exception:
            # Fallback to basic representation if conversion fails
            ret = f'name: {self.name}, access: {self.access}'
            ret += f', address: {self.address}, limit: {self.limit}'
            ret += f', config: {self.config}'
            return ret

    def __repr__(self) -> str:
        """Return detailed string representation."""
        return (f"MemoryConfig(name='{self.name}', access='{self.access}', "
                f"address={self.address}, limit={self.limit}, "
                f"config_count={len(self.config)})")
