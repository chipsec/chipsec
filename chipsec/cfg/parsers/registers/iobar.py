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
I/O BAR Register configuration parser and accessor.

This module provides IOBARRegisters class for parsing and accessing I/O Base Address Register (BAR) registers
in the CHIPSEC framework. I/O BAR registers provide access to device registers through I/O port spaces.
"""

from typing import Dict, Any, Optional, Tuple
from chipsec.library.register import BaseConfigRegisterHelper
from chipsec.library.exceptions import CSConfigError
from chipsec.chipset import cs


class IOBARRegisterError(CSConfigError):
    """Exception raised for I/O BAR register-specific errors."""
    pass


class IOBARRegisters(BaseConfigRegisterHelper):
    """
    I/O BAR Register configuration parser and accessor.

    This class handles parsing and access to I/O Base Address Register (BAR) registers,
    extending the base register helper with I/O BAR-specific functionality.

    Attributes:
        name (str): The name of the register
        desc (str): Description of the register
        size (int): Size of the register in bytes
        offset (int): Offset within the I/O BAR
        bar (str): BAR identifier or name
        bar_base (Optional[int]): Base address of the I/O BAR
        bar_size (Optional[int]): Size of the I/O BAR
        io_port (Optional[int]): Effective I/O port address
        value (Optional[int]): Current register value
        default (Optional[int]): Default register value

    Example:
        >>> iobar_reg = IOBARRegisters({
        ...     'name': 'CMD_REG', 'size': 4, 'offset': 0x04, 'bar': 'BAR0',
        ...     'FIELDS': {}
        ... })
        >>> value = iobar_reg.read()
    """

    def __init__(self, cfg_obj: Dict[str, Any]) -> None:
        """
        Initialize I/O BAR register configuration.

        Args:
            cfg_obj: Dictionary containing I/O BAR register configuration data

        Raises:
            IOBARRegisterError: If configuration validation fails
        """
        try:
            super().__init__(cfg_obj)
            self.size = cfg_obj['size']
            self.offset = cfg_obj['offset']
            self.bar = cfg_obj['bar']
            self.bar_base: Optional[int] = None
            self.bar_size: Optional[int] = None
            self.io_port: Optional[int] = None
            self._validate_iobar_config()
        except KeyError as e:
            raise IOBARRegisterError(f"Missing required field in I/O BAR register configuration: {e}") from e
        except Exception as e:
            raise IOBARRegisterError(f"Failed to initialize I/O BAR register configuration: {e}") from e

    def _validate_iobar_config(self) -> None:
        """
        Validate I/O BAR register-specific configuration requirements.

        Raises:
            IOBARRegisterError: If configuration is invalid
        """
        if not self.name:
            raise IOBARRegisterError("I/O BAR register configuration must have a valid name")

        if not isinstance(self.size, int) or self.size not in [1, 2, 4, 8]:
            raise IOBARRegisterError(f"Invalid register size: {self.size}. Must be 1, 2, 4, or 8 bytes")

        if not isinstance(self.offset, int) or self.offset < 0:
            raise IOBARRegisterError(f"Invalid offset: {self.offset}. Must be a non-negative integer")

        if not self.bar:
            raise IOBARRegisterError("I/O BAR register configuration must have a valid BAR identifier")

    def get_bar_info(self) -> Tuple[Optional[int], Optional[int]]:
        """
        Get BAR base address and size information.

        Returns:
            Tuple of (base_address, size) or (None, None) if not available
        """
        return (self.bar_base, self.bar_size)

    def get_effective_port(self) -> Optional[int]:
        """
        Get the effective I/O port address.

        Returns:
            Effective I/O port address, or None if not computed yet
        """
        return self.io_port

    def get_effective_port_hex(self) -> str:
        """
        Get the effective I/O port address as hexadecimal string.

        Returns:
            Effective I/O port address as hex string, or 'Unknown' if not available
        """
        return f"0x{self.io_port:X}" if self.io_port is not None else "Unknown"

    def is_bar_resolved(self) -> bool:
        """
        Check if the BAR has been resolved to a base address.

        Returns:
            True if BAR base address is available, False otherwise
        """
        return self.bar_base is not None

    def is_valid_port(self) -> bool:
        """
        Check if the effective port address is valid for I/O operations.

        Returns:
            True if port address is valid, False otherwise
        """
        return self.io_port is not None and 0 <= self.io_port <= 0xFFFF

    def _resolve_bar_address(self) -> None:
        """
        Resolve the BAR base address using CHIPSEC HAL.

        Raises:
            IOBARRegisterError: If BAR resolution fails
        """
        try:
            _cs = cs()
            (self.bar_base, self.bar_size) = _cs.hals.IOBAR.get_IO_BAR_base_address(self.bar, self.get_instance())
            self.io_port = self.bar_base + self.offset
        except Exception as e:
            raise IOBARRegisterError(f"Failed to resolve BAR {self.bar} for register {self.name}: {e}") from e

    def __repr__(self) -> str:
        """
        Detailed string representation for debugging.

        Returns:
            Formatted string with register details including fields
        """
        if self.value is not None:
            reg_val_str = f'0x{self.value:0{self.size * 2}X}'
        else:
            reg_val_str = str(self.value)

        instance = f'{self.instance}' if self.instance is not None else 'Fixed'

        if self.default is not None:
            default = f'{self.default:X}'
        else:
            default = 'Not Provided'

        reg_str = (f'[*] {self.name} = {reg_val_str} << {self.desc} '
                  f'({self.bar} + 0x{self.offset:X} Bus {instance}) [default: {default}]')

        reg_str += self._register_fields_str(True)
        return reg_str

    def __str__(self) -> str:
        """
        String representation of I/O BAR register.

        Returns:
            Formatted string with register details
        """
        if self.value is not None:
            reg_val_str = f'0x{self.value:0{self.size * 2}X}'
        else:
            reg_val_str = str(self.value)

        instance = f'{self.instance}' if self.instance is not None else 'Fixed'
        reg_str = f'[*] {self.name} = {reg_val_str} << {self.desc} ({self.bar} + 0x{self.offset:X} Bus {instance})'

        reg_str += self._register_fields_str()
        return reg_str

    def read(self) -> int:
        """
        Read the I/O BAR register value.

        Returns:
            Current register value

        Raises:
            IOBARRegisterError: If read operation fails
        """
        try:
            self.logger.log_debug(f'reading {self.name}')

            # Resolve BAR address if not already done
            if self.io_port is None:
                self._resolve_bar_address()

            if not self.is_valid_port():
                raise IOBARRegisterError(f"Invalid I/O port for register {self.name}: {self.get_effective_port_hex()}")

            _cs = cs()
            self.value = _cs.hals.Io.read(self.io_port, self.size)
            self.logger.log_debug('done reading')

            return self.value
        except Exception as e:
            raise IOBARRegisterError(f"Failed to read I/O BAR register {self.name}: {e}") from e

    def write(self, value: int) -> None:
        """
        Write a value to the I/O BAR register.

        Args:
            value: Value to write to the register

        Raises:
            IOBARRegisterError: If write operation fails
        """
        try:
            self.logger.log_debug(f'writing 0x{value:X} to {self.name}')

            # Resolve BAR address if not already done
            if self.io_port is None:
                self._resolve_bar_address()

            if not self.is_valid_port():
                raise IOBARRegisterError(f"Invalid I/O port for register {self.name}: {self.get_effective_port_hex()}")

            _cs = cs()
            _cs.hals.Io.write(self.io_port, value, self.size)
            self.value = value

        except Exception as e:
            raise IOBARRegisterError(f"Failed to write to I/O BAR register {self.name}: {e}") from e
