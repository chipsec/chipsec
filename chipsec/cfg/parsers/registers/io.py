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
I/O Register configuration parser and accessor.

This module provides IORegisters class for parsing and accessing I/O port-based registers
in the CHIPSEC framework. I/O registers are accessed through CPU I/O port instructions.
"""

from typing import Dict, Any
from chipsec.library.register import BaseConfigRegisterHelper
from chipsec.library.exceptions import CSConfigError
from chipsec.chipset import cs


class IORegisterError(CSConfigError):
    """Exception raised for I/O register-specific errors."""
    pass


class IORegisters(BaseConfigRegisterHelper):
    """
    I/O Register configuration parser and accessor.

    This class handles parsing and access to I/O port-based registers, extending
    the base register helper with I/O-specific functionality.

    Attributes:
        name (str): The name of the register
        desc (str): Description of the register
        io_port (int): I/O port address
        size (int): Size of the register in bytes
        value (Optional[int]): Current register value
        default (Optional[int]): Default register value
        bar_size (Optional[int]): BAR size (always None for I/O registers)

    Example:
        >>> io_reg = IORegisters({'name': 'PM1_STS', 'port': 0x400, 'size': 2})
        >>> value = io_reg.read()
    """

    def __init__(self, cfg_obj: Dict[str, Any]) -> None:
        """
        Initialize I/O register configuration.

        Args:
            cfg_obj: Dictionary containing I/O register configuration data

        Raises:
            IORegisterError: If configuration validation fails
        """
        try:
            super().__init__(cfg_obj)
            self.io_port = cfg_obj['port']
            self.size = cfg_obj['size']
            self.bar_size = None  # I/O registers don't have BAR size
            self._validate_io_config()
        except KeyError as e:
            raise IORegisterError(f"Missing required field in I/O register configuration: {e}") from e
        except Exception as e:
            raise IORegisterError(f"Failed to initialize I/O register configuration: {e}") from e

    def _validate_io_config(self) -> None:
        """
        Validate I/O register-specific configuration requirements.

        Raises:
            IORegisterError: If configuration is invalid
        """
        if not self.name:
            raise IORegisterError("I/O register configuration must have a valid name")

        if not isinstance(self.io_port, int) or self.io_port < 0 or self.io_port > 0xFFFF:
            raise IORegisterError(f"Invalid I/O port: {self.io_port}. Must be 0-65535 range")

        if not isinstance(self.size, int) or self.size not in [1, 2, 4]:
            raise IORegisterError(f"Invalid register size: {self.size}. Must be 1, 2, or 4 bytes")

    def get_port_address(self) -> int:
        """
        Get the I/O port address.

        Returns:
            I/O port address as integer
        """
        return self.io_port

    def get_port_hex(self) -> str:
        """
        Get the I/O port address as hexadecimal string.

        Returns:
            I/O port address as hex string (e.g., '0x400')
        """
        return f"0x{self.io_port:X}"

    def is_valid_port(self) -> bool:
        """
        Check if the I/O port address is valid.

        Returns:
            True if port is valid, False otherwise
        """
        return isinstance(self.io_port, int) and 0 <= self.io_port <= 0xFFFF

    def __repr__(self) -> str:
        """
        Detailed string representation for debugging.

        Returns:
            Formatted string with register details including fields
        """
        reg_str = ''
        if self.value is not None:
            reg_val_str = f'0x{self.value:0{self.size * 2}X}'
        else:
            reg_val_str = str(self.value)

        if self.default is not None:
            default = f'{self.default:X}'
        else:
            default = 'Not Provided'

        reg_str = (f'[*] {self.name} = {reg_val_str} << {self.desc} '
                  f'(I/O port 0x{self.io_port:X}) [default: {default}]')

        reg_str += self._register_fields_str(True)
        return reg_str

    def __str__(self) -> str:
        """
        String representation of I/O register.

        Returns:
            Formatted string with register details
        """
        reg_str = ''
        if self.value is not None:
            reg_val_str = f'0x{self.value:0{self.size * 2}X}'
        else:
            reg_val_str = str(self.value)

        reg_str = f'[*] {self.name} = {reg_val_str} << {self.desc} (I/O port 0x{self.io_port:X})'

        reg_str += self._register_fields_str()
        return reg_str

    def read(self) -> int:
        """
        Read the I/O register value.

        Returns:
            Current register value

        Raises:
            IORegisterError: If read operation fails
        """
        try:
            self.logger.log_debug(f'reading {self.name}')
            _cs = cs()
            self.value = _cs.hals.Io.read(self.io_port, self.size)
            return self.value
        except Exception as e:
            raise IORegisterError(f"Failed to read I/O register {self.name} at port 0x{self.io_port:X}: {e}") from e

    def write(self, value: int) -> None:
        """
        Write a value to the I/O register.

        Args:
            value: Value to write to the register

        Raises:
            IORegisterError: If write operation fails
        """
        try:
            self.logger.log_debug(f'writing 0x{value:X} to {self.name}')
            _cs = cs()
            _cs.hals.Io.write(self.io_port, value, self.size)
            self.value = value
        except Exception as e:
            raise IORegisterError(f"Failed to write to I/O register {self.name} at port 0x{self.io_port:X}: {e}") from e
