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
MSR Register configuration parser and accessor.

This module provides MSRRegisters class for parsing and accessing Model Specific Registers (MSRs)
in the CHIPSEC framework. MSR registers provide access to processor-specific configuration and
control settings.
"""

from typing import Dict, Any, Tuple
from chipsec.chipset import cs
from chipsec.library.register import BaseConfigRegisterHelper
from chipsec.library.exceptions import MSRRegisterError

class MSRRegisters(BaseConfigRegisterHelper):
    """
    MSR Register configuration parser and accessor.

    This class handles parsing and access to Model Specific Registers (MSRs), extending
    the base register helper with MSR-specific functionality including thread management
    and MSR protocol operations.

    Attributes:
        name (str): The name of the register
        desc (str): Description of the register
        size (int): Size of the register in bytes (default 8 for MSRs)
        thread (int): Thread/CPU instance identifier
        msr (int): MSR register number
        value (int): Current register value
        default (int): Default register value

    Example:
        >>> msr_reg = MSRRegisters({
        ...     'name': 'IA32_FEATURE_CONTROL', 'msr': 0x3A, 'instance': 0
        ... })
        >>> value = msr_reg.read()
    """

    def __init__(self, cfg_obj: Dict[str, Any]) -> None:
        """
        Initialize MSR register configuration.

        Args:
            cfg_obj: Dictionary containing MSR register configuration data

        Raises:
            MSRRegisterError: If configuration validation fails
        """
        try:
            super().__init__(cfg_obj)
            self.size = cfg_obj.get('size', 8)  # MSRs are typically 8 bytes
            self.thread = cfg_obj['instance']
            self.msr = cfg_obj['msr']
            self._validate_msr_config()
        except KeyError as e:
            raise MSRRegisterError(f"Missing required field in MSR register configuration: {e}") from e
        except Exception as e:
            raise MSRRegisterError(f"Failed to initialize MSR register configuration: {e}") from e

    def _validate_msr_config(self) -> None:
        """
        Validate MSR register-specific configuration requirements.

        Raises:
            MSRRegisterError: If configuration is invalid
        """
        if not self.name:
            raise MSRRegisterError("MSR register configuration must have a valid name")

        if not isinstance(self.thread, int) or self.thread < 0:
            raise MSRRegisterError(f"Thread/Instance for {self.name} is invalid: {self.thread}. Must be a non-negative integer")

        if not isinstance(self.msr, int) or self.msr < 0:
            raise MSRRegisterError(f"MSR number for {self.name} is invalid: {self.msr}. Must be a non-negative integer")

        if not isinstance(self.size, int) or self.size not in [1, 2, 4, 8]:
            raise MSRRegisterError(f"Size for {self.name} is invalid: {self.size}. Must be 1, 2, 4, or 8 bytes")

    def get_msr_hex(self) -> str:
        """
        Get the MSR number as hexadecimal string.

        Returns:
            MSR number as hex string (e.g., '0x3A')
        """
        return f"0x{self.msr:X}"

    def get_thread_hex(self) -> str:
        """
        Get the thread/instance as hexadecimal string.

        Returns:
            Thread number as hex string (e.g., '0x0')
        """
        return f"0x{self.thread:X}"

    def get_address_info(self) -> str:
        """
        Get formatted address information for this register.

        Returns:
            Formatted string with MSR and thread information
        """
        return f"MSR {self.get_msr_hex()} Thread {self.get_thread_hex()}"

    def _get_formatted_value(self) -> str:
        """
        Get formatted register value based on size.

        Returns:
            Formatted value string
        """
        if self.value is not None:
            return f'0x{self.value:0{self.size * 2}X}'
        return str(self.value)

    def _split_64bit_value(self, value: int) -> Tuple[int, int]:
        """
        Split a 64-bit value into EAX (low 32-bits) and EDX (high 32-bits).

        Args:
            value: 64-bit value to split

        Returns:
            Tuple of (eax, edx) values
        """
        eax = value & 0xFFFFFFFF
        edx = (value >> 32) & 0xFFFFFFFF
        return eax, edx

    def _combine_32bit_values(self, eax: int, edx: int) -> int:
        """
        Combine EAX and EDX values into a 64-bit value.

        Args:
            eax: Low 32-bit value
            edx: High 32-bit value

        Returns:
            Combined 64-bit value
        """
        return (edx << 32) | eax

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
        String representation of MSR register.

        Returns:
            Formatted string with register details
        """
        reg_val_str = self._get_formatted_value()

        reg_str = (f'[*] {self.name} = {reg_val_str} << {self.desc} '
                   f'({self.get_address_info()})')

        reg_str += self._register_fields_str()
        return reg_str

    def read(self) -> int:
        """
        Read the MSR register value.

        Returns:
            Current register value

        Raises:
            MSRRegisterError: If read operation fails
        """
        try:
            self.logger.log_debug(f'reading {self.name}')
            _cs = cs()
            eax, edx = _cs.hals.msr.read_msr(self.thread, self.msr)
            self.value = self._combine_32bit_values(eax, edx)
            return self.value
        except Exception as e:
            raise MSRRegisterError(
                f"Failed to read MSR register {self.name} at {self.get_address_info()}: {e}"
            ) from e

    def write(self, value: int) -> None:
        """
        Write a value to the MSR register.

        Args:
            value: Value to write to the register

        Raises:
            MSRRegisterError: If write operation fails
        """
        try:
            self.logger.log_debug(f'writing 0x{value:X} to {self.name}')
            _cs = cs()
            eax, edx = self._split_64bit_value(value)
            _cs.hals.msr.write(self.thread, self.msr, eax, edx)
            self.value = value
        except Exception as e:
            raise MSRRegisterError(
                f"Failed to write to MSR register {self.name} at {self.get_address_info()}: {e}"
            ) from e
