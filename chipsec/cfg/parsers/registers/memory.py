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
Memory Register configuration parser and accessor.

This module provides MEMORYRegisters class for parsing and accessing memory-mapped registers
in the CHIPSEC framework. Memory registers can be accessed through DRAM or MMIO methods.
"""

from typing import Dict, Any
from chipsec.library.exceptions import CSConfigError
from chipsec.library.register import BaseConfigRegisterHelper
from chipsec.chipset import cs


class MemoryRegisterError(CSConfigError):
    """Exception raised for memory register-specific errors."""
    pass


class MEMORYRegisters(BaseConfigRegisterHelper):
    """
    Memory Register configuration parser and accessor.

    This class handles parsing and access to memory-mapped registers, extending
    the base register helper with memory-specific functionality including both
    DRAM and MMIO access methods.

    Attributes:
        name (str): The name of the register
        desc (str): Description of the register
        offset (int): Offset within the memory range
        range (int): Memory range identifier
        size (int): Size of the register in bytes
        address (int): Base memory address
        limit (int): Memory limit
        access (str): Access method ('dram' or 'mmio')
        value (int): Current register value
        default (int): Default register value

    Example:
        >>> mem_reg = MEMORYRegisters({
        ...     'name': 'TOLUD', 'address': 0xFED00000, 'offset': 0x100,
        ...     'size': 4, 'access': 'mmio'
        ... })
        >>> value = mem_reg.read()
    """

    def __init__(self, cfg_obj: Dict[str, Any]) -> None:
        """
        Initialize memory register configuration.

        Args:
            cfg_obj: Dictionary containing memory register configuration data

        Raises:
            MemoryRegisterError: If configuration validation fails
        """
        try:
            super().__init__(cfg_obj)
            self.offset = cfg_obj['offset']
            self.range = cfg_obj['range']
            self.size = cfg_obj['size']
            self.address = cfg_obj['address']
            self.limit = cfg_obj['limit']
            self.access = cfg_obj['access']
            self._validate_memory_config()
        except KeyError as e:
            raise MemoryRegisterError(f"Missing required field in memory register configuration: {e}") from e
        except Exception as e:
            raise MemoryRegisterError(f"Failed to initialize memory register configuration: {e}") from e

    def _validate_memory_config(self) -> None:
        """
        Validate memory register-specific configuration requirements.

        Raises:
            MemoryRegisterError: If configuration is invalid
        """
        if not self.name:
            raise MemoryRegisterError("Memory register configuration must have a valid name")

        if not isinstance(self.address, int) or self.address < 0:
            raise MemoryRegisterError(f"Invalid address: {self.address}. Must be a positive integer")

        if not isinstance(self.offset, int) or self.offset < 0:
            raise MemoryRegisterError(f"Invalid offset: {self.offset}. Must be a non-negative integer")

        if not isinstance(self.size, int) or self.size not in [1, 2, 4, 8]:
            raise MemoryRegisterError(f"Invalid register size: {self.size}. Must be 1, 2, 4, or 8 bytes")

        if self.access not in ['dram', 'mmio']:
            raise MemoryRegisterError(f"Invalid access method: {self.access}. Must be 'dram' or 'mmio'")

    def get_physical_address(self) -> int:
        """
        Get the physical memory address (base + offset).

        Returns:
            Physical memory address as integer
        """
        return self.address + self.offset

    def get_address_hex(self) -> str:
        """
        Get the physical memory address as hexadecimal string.

        Returns:
            Physical memory address as hex string (e.g., '0xFED00100')
        """
        return f"0x{self.get_physical_address():X}"

    def is_dram_access(self) -> bool:
        """
        Check if this register uses DRAM access method.

        Returns:
            True if access method is 'dram', False otherwise
        """
        return self.access == 'dram'

    def is_mmio_access(self) -> bool:
        """
        Check if this register uses MMIO access method.

        Returns:
            True if access method is 'mmio', False otherwise
        """
        return self.access == 'mmio'

    def __repr__(self) -> str:
        """
        Detailed string representation for debugging.

        Returns:
            Formatted string with register details including fields
        """
        reg_str = ''
        if self.value is not None:
            reg_val_str = f'0x{self.value:08X}'
        else:
            reg_val_str = str(self.value)

        if self.default is not None:
            default = f'{self.default:X}'
        else:
            default = 'Not Provided'

        reg_str = (f'[*] {self.name} = {reg_val_str} << {self.desc} '
                  f'(0x{self.address:X} + 0x{self.offset:X}) [default: {default}]')

        reg_str += self._register_fields_str(True)
        return reg_str

    def __str__(self) -> str:
        """
        String representation of memory register.

        Returns:
            Formatted string with register details
        """
        reg_str = ''
        if self.value is not None:
            reg_val_str = f'0x{self.value:08X}'
        else:
            reg_val_str = str(self.value)

        reg_str = f'[*] {self.name} = {reg_val_str} << {self.desc} (0x{self.address:X} + 0x{self.offset:X})'

        reg_str += self._register_fields_str()
        return reg_str

    def read(self) -> int:
        """
        Read the memory register value.

        Returns:
            Current register value

        Raises:
            MemoryRegisterError: If read operation fails
        """
        try:
            self.logger.log_debug(f'reading {self.name}')
            _cs = cs()

            if self.access == 'dram':
                self.value = _cs.hals.MemRange.read(self.address + self.offset, self.size)
            elif self.access == 'mmio':
                self.value = _cs.hals.MMIO.read_MMIO_reg(self.address, self.offset, self.size)
            else:
                raise MemoryRegisterError(f"Unsupported access method: {self.access}")

            return self.value
        except Exception as e:
            raise MemoryRegisterError(f"Failed to read memory register {self.name} at {self.get_address_hex()}: {e}") from e

    def write(self, value: int) -> None:
        """
        Write a value to the memory register.

        Args:
            value: Value to write to the register

        Raises:
            MemoryRegisterError: If write operation fails
        """
        try:
            self.logger.log_debug(f'writing 0x{value:X} to {self.name}')
            _cs = cs()

            if self.access == 'dram':
                _cs.hals.Memory.write_physical_mem(self.address + self.offset, self.size, value)
            elif self.access == 'mmio':
                _cs.hals.MMIO.write_MMIO_reg(self.address, self.offset, value, self.size, None)
            else:
                raise MemoryRegisterError(f"Unsupported access method: {self.access}")

            self.value = value
        except Exception as e:
            raise MemoryRegisterError(f"Failed to write to memory register {self.name} at {self.get_address_hex()}: {e}") from e
