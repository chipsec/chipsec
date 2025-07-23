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
MSGBUS Register configuration parser and accessor.

This module provides MSGBUSRegisters class for parsing and accessing message bus registers
in the CHIPSEC framework. Message bus registers provide access to various hardware interfaces
through Intel's Message Bus protocol.
"""

from typing import Dict, Any
from chipsec.chipset import cs
from chipsec.library.register import BaseConfigRegisterHelper
from chipsec.library.exceptions import MSGBUSRegisterError

class MSGBUSRegisters(BaseConfigRegisterHelper):
    """
    MSGBUS Register configuration parser and accessor.

    This class handles parsing and access to message bus registers, extending the base
    register helper with MSGBUS-specific functionality including port management and
    message bus protocol operations.

    Attributes:
        name (str): The name of the register
        desc (str): Description of the register
        offset (int): Offset within the MSGBUS address space
        port (int): MSGBUS port identifier
        value (int): Current register value
        default (int): Default register value
        bar_size (Optional[int]): Size of the BAR (if applicable)

    Example:
        >>> msgbus_reg = MSGBUSRegisters({
        ...     'name': 'PUNIT_REG', 'port': 0x04, 'offset': 0x100
        ... })
        >>> value = msgbus_reg.read()
    """

    def __init__(self, cfg_obj: Dict[str, Any]) -> None:
        """
        Initialize MSGBUS register configuration.

        Args:
            cfg_obj: Dictionary containing MSGBUS register configuration data

        Raises:
            MSGBUSRegisterError: If configuration validation fails
        """
        try:
            super().__init__(cfg_obj)
            self.offset = cfg_obj['offset']
            self.port = cfg_obj['port']
            self.bar_size = None
            self._validate_msgbus_config()
        except KeyError as e:
            raise MSGBUSRegisterError(f"Missing required field in MSGBUS register configuration: {e}") from e
        except Exception as e:
            raise MSGBUSRegisterError(f"Failed to initialize MSGBUS register configuration: {e}") from e

    def _validate_msgbus_config(self) -> None:
        """
        Validate MSGBUS register-specific configuration requirements.

        Raises:
            MSGBUSRegisterError: If configuration is invalid
        """
        if not self.name:
            raise MSGBUSRegisterError("MSGBUS register configuration must have a valid name")

        if not isinstance(self.offset, int) or self.offset < 0:
            raise MSGBUSRegisterError(f"Offset for {self.name} is invalid: {self.offset}. Must be a non-negative integer")

        if not isinstance(self.port, int) or self.port < 0:
            raise MSGBUSRegisterError(f"Port for {self.name} is invalid: {self.port}. Must be a non-negative integer")

    def get_port_hex(self) -> str:
        """
        Get the MSGBUS port as hexadecimal string.

        Returns:
            Port as hex string (e.g., '0x04')
        """
        return f"0x{self.port:X}"

    def get_offset_hex(self) -> str:
        """
        Get the register offset as hexadecimal string.

        Returns:
            Offset as hex string (e.g., '0x100')
        """
        return f"0x{self.offset:X}"

    def get_address_info(self) -> str:
        """
        Get formatted address information for this register.

        Returns:
            Formatted string with port and offset information
        """
        return f"mm_msgbus port {self.get_port_hex()}, off {self.get_offset_hex()}"

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
                   f'({self.get_address_info()}) [default: {default}]')

        reg_str += self._register_fields_str(True)
        return reg_str

    def __str__(self) -> str:
        """
        String representation of MSGBUS register.

        Returns:
            Formatted string with register details
        """
        reg_str = ''
        if self.value is not None:
            reg_val_str = f'0x{self.value:08X}'
        else:
            reg_val_str = str(self.value)

        reg_str = (f'[*] {self.name} = {reg_val_str} << {self.desc} '
                   f'({self.get_address_info()})')

        reg_str += self._register_fields_str()
        return reg_str

    def read(self) -> int:
        """
        Read the MSGBUS register value.

        Returns:
            Current register value

        Raises:
            MSGBUSRegisterError: If read operation fails
        """
        try:
            self.logger.log_debug(f'reading {self.name}')
            _cs = cs()
            self.value = _cs.hals.MsgBus.msgbus_reg_read(self.port, self.offset)
            return self.value
        except Exception as e:
            raise MSGBUSRegisterError(
                f"Failed to read MSGBUS register {self.name} at {self.get_address_info()}: {e}"
            ) from e

    def write(self, value: int) -> None:
        """
        Write a value to the MSGBUS register.

        Args:
            value: Value to write to the register

        Raises:
            MSGBUSRegisterError: If write operation fails
        """
        try:
            self.logger.log_debug(f'writing 0x{value:X} to {self.name}')
            _cs = cs()
            _cs.hals.MsgBus.msgbus_reg_write(self.port, self.offset, value)
            self.value = value
        except Exception as e:
            raise MSGBUSRegisterError(
                f"Failed to write to MSGBUS register {self.name} at {self.get_address_info()}: {e}"
            ) from e
