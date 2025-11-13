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
MMIO Register configuration parser and accessor.

This module provides MMIORegisters class for parsing and accessing Memory-Mapped I/O registers
in the CHIPSEC framework. MMIO registers provide access to hardware interfaces through
memory-mapped address spaces.
"""

from typing import Dict, Any
from chipsec.chipset import cs
from chipsec.library.register import BaseConfigRegisterHelper
from chipsec.library.exceptions import MMIORegisterError

class MMIORegisters(BaseConfigRegisterHelper):
    """
    MMIO Register configuration parser and accessor.

    This class handles parsing and access to Memory-Mapped I/O registers, extending
    the base register helper with MMIO-specific functionality including BAR management,
    memory range handling, and MMIO protocol operations.

    Attributes:
        name (str): The name of the register
        desc (str): Description of the register
        size (int): Size of the register in bytes
        offset (int): Offset within the MMIO address space
        bar (Optional[str]): BAR identifier for MMIO access
        range (Optional[str]): Memory range identifier
        bar_base (Optional[int]): Base address of the BAR
        bar_size (Optional[int]): Size of the BAR
        value (int): Current register value
        default (int): Default register value
        instance: Instance identifier for the register
        cs: Chipset interface object

    Example:
        >>> mmio_reg = MMIORegisters({
        ...     'name': 'MMIO_REG', 'size': 4, 'offset': 0x100, 'bar': 'MMIO_BAR'
        ... })
        >>> value = mmio_reg.read()
    """

    def __init__(self, cfg_obj: Dict[str, Any]) -> None:
        """
        Initialize MMIO register configuration.

        Args:
            cfg_obj: Dictionary containing MMIO register configuration data

        Raises:
            MMIORegisterError: If configuration validation fails
        """
        try:
            super().__init__(cfg_obj)
            self.cs = cs()
            self.size = cfg_obj['size']
            self.offset = cfg_obj['offset']
            self.bar_base = None
            self.bar_size = None
            self.bar = cfg_obj.get('bar')
            self.range = cfg_obj.get('range')
            self._validate_mmio_config()
        except KeyError as e:
            raise MMIORegisterError(f"Missing required field in MMIO register configuration: {e}") from e
        except Exception as e:
            raise MMIORegisterError(f"Failed to initialize MMIO register configuration: {e}") from e

    def is_enabled(self) -> bool:
        """Check if the MMIO register is enabled."""
        try:
            self.populate_base_address()
        except Exception as e:
            return False
        return self.bar_base is not None

    def _validate_mmio_config(self) -> None:
        """
        Validate MMIO register-specific configuration requirements.

        Raises:
            MMIORegisterError: If configuration is invalid
        """
        if not self.name:
            raise MMIORegisterError("MMIO register configuration must have a valid name")

        if not isinstance(self.size, int) or self.size not in [1, 2, 4, 8]:
            raise MMIORegisterError(f"Size for {self.name} is invalid: {self.size}. Must be 1, 2, 4, or 8 bytes")

        if not isinstance(self.offset, int) or self.offset < 0:
            raise MMIORegisterError(f"Offset for {self.name} is invalid: {self.offset}. Must be a non-negative integer")

        if not self.bar and not self.range:
            raise MMIORegisterError(f"MMIO register {self.name} must specify either 'bar' or 'range'")

        if self.bar and self.range:
            raise MMIORegisterError(f"MMIO register {self.name} cannot specify both 'bar' and 'range'")

    def get_offset_hex(self) -> str:
        """
        Get the register offset as hexadecimal string.

        Returns:
            Offset as hex string (e.g., '0x100')
        """
        return f"0x{self.offset:X}"

    def get_instance_str(self) -> str:
        """
        Get the instance as a formatted string.

        Returns:
            Instance as string ('Fixed' if None, otherwise the instance value)
        """
        return f'{self.instance}' if self.instance is not None else 'Fixed'

    def get_address_info(self) -> str:
        """
        Get formatted address information for this register.

        Returns:
            Formatted string with BAR/range and offset information
        """
        if self.bar:
            return f"{self.bar} + {self.get_offset_hex()} {self.get_instance_str()}"
        elif self.range:
            return f"Range:{self.range} + {self.get_offset_hex()} {self.get_instance_str()}"
        else:
            return f"Unknown + {self.get_offset_hex()} {self.get_instance_str()}"

    def _get_formatted_value(self) -> str:
        """
        Get formatted register value based on size.

        Returns:
            Formatted value string
        """
        if self.value is not None:
            return f'0x{self.value:0{self.size * 2}X}'
        return str(self.value)

    def __repr__(self) -> str:
        """
        Detailed string representation for debugging.

        Returns:
            Formatted string with register details including fields
        """
        reg_val_str = self._get_formatted_value()

        if self.default is not None:
            default = f'{self.default:X}'
        else:
            default = 'Not Provided'

        reg_str = (f'[*] {self.name} = {reg_val_str} << {self.desc} '
                   f'({self.get_address_info()}) [default: {default}]')

        reg_str += self._register_fields_str(True)
        return reg_str

    def __str__(self) -> str:
        """
        String representation of MMIO register.

        Returns:
            Formatted string with register details
        """
        reg_val_str = self._get_formatted_value()

        reg_str = (f'[*] {self.name} = {reg_val_str} << {self.desc} '
                   f'({self.get_address_info()})')

        reg_str += self._register_fields_str()
        return reg_str

    def get_instance(self) -> Any:
        """
        Get the instance value, handling nested instance attributes.

        Returns:
            The instance value
        """
        return self.instance if not hasattr(self.instance, 'instance') else self.instance.instance

    def populate_base_address(self) -> None:
        """
        Populate the base address for MMIO operations.

        This method resolves the BAR or memory range to get the actual base address
        for MMIO register access.

        Raises:
            MMIORegisterError: If base address cannot be populated
        """
        if self.bar_base is not None:
            return  # Already populated

        try:
            if self.bar:
                self.bar_base, self.bar_size = self.cs.hals.mmio.get_MMIO_BAR_base_address(
                    self.bar, self.get_instance()
                )
            elif self.range:
                mem_range_def = self.cs.hals.memrange.get_def(self.range)
                if mem_range_def:
                    if mem_range_def.access == 'mmio':
                        self.bar_size = mem_range_def.size
                        self.bar_base = mem_range_def.address
                    else:
                        raise MMIORegisterError(
                            f"Memory Range ({self.range}) access type ({mem_range_def.access}) is not MMIO."
                        )
                else:
                    raise MMIORegisterError(f"Memory Range ({self.range}) cannot be found.")
            else:
                raise MMIORegisterError(f"Unable to populate MMIO Base Address: {self.name}")
        except Exception as e:
            raise MMIORegisterError(f"Failed to populate base address for {self.name}: {e}") from e

    def read(self) -> int:
        """
        Read the MMIO register value.

        Returns:
            Current register value

        Raises:
            MMIORegisterError: If read operation fails
        """
        try:
            self.logger.log_debug(f'reading {self.name}')
            self.populate_base_address()
            self.value = self.cs.hals.mmio.read_MMIO_reg(self.bar_base, self.offset, self.size)
            self.logger.log_debug('done reading')
            return self.value
        except Exception as e:
            raise MMIORegisterError(f"Failed to read MMIO register {self.name}: {e}") from e

    def write(self, value: int) -> None:
        """
        Write a value to the MMIO register.

        Args:
            value: Value to write to the register

        Raises:
            MMIORegisterError: If write operation fails
        """
        try:
            self.logger.log_debug(f'writing 0x{value:X} to {self.name}')
            self.populate_base_address()
            self.cs.hals.mmio.write_MMIO_reg(self.bar_base, self.offset, value, self.size)
            self.value = value
        except Exception as e:
            raise MMIORegisterError(f"Failed to write to MMIO register {self.name}: {e}") from e

    def write_subset(self, value: int, size: int, offset: int = 0) -> None:
        """
        Write a subset of the MMIO register.

        Args:
            value: Value to write
            size: Size of the write operation in bytes
            offset: Offset within the register for the write operation

        Raises:
            MMIORegisterError: If write operation fails or parameters are invalid
        """
        try:
            if offset < 0 or size <= 0:
                raise MMIORegisterError("Offset must be non-negative and size must be positive")

            if offset >= self.size or size > self.size - offset:
                raise MMIORegisterError(
                    f"Improper Offset ({offset}) or Size ({size}) requested in write subset for {self.name}. "
                    f"Register size is {self.size} bytes."
                )

            self.logger.log_debug(f'writing subset 0x{value:X} to {self.name} at offset {offset}, size {size}')
            self.populate_base_address()
            self.cs.hals.mmio.write_MMIO_reg(self.bar_base, self.offset + offset, value, size)
        except Exception as e:
            raise MMIORegisterError(f"Failed to write subset to MMIO register {self.name}: {e}") from e
