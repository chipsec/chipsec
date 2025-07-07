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
MMCFG Register configuration parser and accessor.

This module provides MMCFGRegisters class for parsing and accessing memory-mapped configuration
space registers in the CHIPSEC framework. MMCFG registers provide access to PCI configuration
space through memory-mapped I/O.
"""

from typing import Dict, Any
from chipsec.chipset import cs
from chipsec.library.register import BaseConfigRegisterHelper
from chipsec.library.exceptions import CSReadError, CSConfigError


class MMCFGRegisterError(CSConfigError):
    """Exception raised for MMCFG register-specific errors."""
    pass


class MMCFGRegisters(BaseConfigRegisterHelper):
    """
    MMCFG Register configuration parser and accessor.

    This class handles parsing and access to memory-mapped configuration space registers,
    extending the base register helper with MMCFG-specific functionality including PCI
    device management and memory-mapped configuration space operations.

    Attributes:
        name (str): The name of the register
        desc (str): Description of the register
        size (int): Size of the register in bytes
        offset (int): Offset within the MMCFG address space
        pci: PCI device object containing bus, device, and function information
        value (int): Current register value
        default (int): Default register value

    Example:
        >>> mmcfg_reg = MMCFGRegisters({
        ...     'name': 'PCI_REG', 'size': 4, 'offset': 0x10
        ... }, pci_obj)
        >>> value = mmcfg_reg.read()
    """

    def __init__(self, cfg_obj: Dict[str, Any], pci_obj: Any) -> None:
        """
        Initialize MMCFG register configuration.

        Args:
            cfg_obj: Dictionary containing MMCFG register configuration data
            pci_obj: PCI device object with bus, device, and function information

        Raises:
            MMCFGRegisterError: If configuration validation fails
        """
        try:
            super().__init__(cfg_obj)
            self.size = cfg_obj['size']
            self.offset = cfg_obj['offset']
            self.pci = pci_obj
            self._validate_mmcfg_config()
        except KeyError as e:
            raise MMCFGRegisterError(f"Missing required field in MMCFG register configuration: {e}") from e
        except Exception as e:
            raise MMCFGRegisterError(f"Failed to initialize MMCFG register configuration: {e}") from e

    def _validate_mmcfg_config(self) -> None:
        """
        Validate MMCFG register-specific configuration requirements.

        Raises:
            MMCFGRegisterError: If configuration is invalid
        """
        if not self.name:
            raise MMCFGRegisterError("MMCFG register configuration must have a valid name")

        if not isinstance(self.size, int) or self.size not in [1, 2, 4, 8]:
            raise MMCFGRegisterError(f"Invalid register size: {self.size}. Must be 1, 2, 4, or 8 bytes")

        if not isinstance(self.offset, int) or self.offset < 0:
            raise MMCFGRegisterError(f"Invalid offset: {self.offset}. Must be a non-negative integer")

        if self.pci is None:
            raise MMCFGRegisterError("PCI object must be provided for MMCFG register")

    def is_device_present(self) -> bool:
        """
        Check if the PCI device is present and accessible.

        Returns:
            True if device is present, False otherwise
        """
        return self.pci is not None and self.pci.bus is not None

    def get_pci_address(self) -> str:
        """
        Get the PCI device address in b:d.f format.

        Returns:
            PCI address string (e.g., '00:1f.0')
        """
        if not self.is_device_present():
            return "Device not present"
        return f"{self.pci.bus:02d}:{self.pci.dev:02d}.{self.pci.fun:d}"

    def get_mmcfg_offset(self) -> int:
        """
        Calculate the MMCFG offset for this register.

        Returns:
            MMCFG offset value
        """
        if not self.is_device_present():
            return 0
        return (self.pci.bus * 32 * 8 + self.pci.dev * 8 + self.pci.fun) * 0x1000 + self.offset

    def get_address_info(self) -> str:
        """
        Get formatted address information for this register.

        Returns:
            Formatted string with PCI and MMCFG address information
        """
        if not self.is_device_present():
            return "Device not present"

        mmcfg_offset = self.get_mmcfg_offset()
        return (f"b:d.f {self.get_pci_address()} + 0x{self.offset:X}, "
                f"MMCFG + 0x{mmcfg_offset:X}")

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
        if not self.is_device_present():
            return 'Device not present'

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
        String representation of MMCFG register.

        Returns:
            Formatted string with register details
        """
        if not self.is_device_present():
            return 'Device not present'

        reg_val_str = self._get_formatted_value()

        reg_str = (f'[*] {self.name} = {reg_val_str} << {self.desc} '
                   f'({self.get_address_info()})')
        reg_str += self._register_fields_str()
        return reg_str

    def read(self) -> int:
        """
        Read the MMCFG register value.

        Returns:
            Current register value

        Raises:
            MMCFGRegisterError: If read operation fails or device is not present
        """
        try:
            self.logger.log_debug(f'reading {self.name}')

            if not self.is_device_present():
                raise MMCFGRegisterError(
                    f'PCI Device is not available ({self.get_pci_address()})'
                )

            _cs = cs()
            self.value = _cs.hals.MMCFG.read_mmcfg_reg(
                self.pci.bus, self.pci.dev, self.pci.fun, self.offset, self.size
            )
            return self.value
        except CSReadError as e:
            raise MMCFGRegisterError(f"Failed to read MMCFG register {self.name}: {e}") from e
        except Exception as e:
            raise MMCFGRegisterError(f"Failed to read MMCFG register {self.name}: {e}") from e

    def write(self, value: int) -> None:
        """
        Write a value to the MMCFG register.

        Args:
            value: Value to write to the register

        Raises:
            MMCFGRegisterError: If write operation fails or device is not present
        """
        try:
            self.logger.log_debug(f'writing 0x{value:X} to {self.name}')

            if not self.is_device_present():
                raise MMCFGRegisterError(
                    f'PCI Device is not available ({self.get_pci_address()})'
                )

            _cs = cs()
            _cs.hals.MMCFG.write_mmcfg_reg(
                self.pci.bus, self.pci.dev, self.pci.fun, self.offset, self.size, value
            )
            self.value = value
        except CSReadError as e:
            raise MMCFGRegisterError(f"Failed to write to MMCFG register {self.name}: {e}") from e
        except Exception as e:
            raise MMCFGRegisterError(f"Failed to write to MMCFG register {self.name}: {e}") from e
