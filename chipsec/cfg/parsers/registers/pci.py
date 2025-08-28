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
PCI Register Configuration Helper

Provides PCI configuration space register-specific functionality.
"""

from typing import Dict, Any, Union

from chipsec.chipset import cs
from chipsec.library.register import BaseConfigRegisterHelper
from chipsec.library.exceptions import CSReadError, CSConfigError, PCIRegisterError


class PCIRegisters(BaseConfigRegisterHelper):
    """
    PCI register configuration helper for PCI configuration space registers.

    Manages PCI configuration space register access including bus, device,
    function addressing and register offset handling.
    """

    def __init__(self, cfg_obj: Dict[str, Any], pci_obj):
        """
        Initialize PCI register configuration helper.

        Args:
            cfg_obj: Configuration object containing PCI register fields
            pci_obj: PCI object containing bus/device/function information

        Raises:
            PCIRegisterError: If PCI register configuration is invalid
        """
        try:
            super().__init__(cfg_obj)

            # Required fields for PCI registers
            required_fields = ['size', 'offset']
            missing_fields = [field for field in required_fields
                              if field not in cfg_obj]
            if missing_fields:
                raise PCIRegisterError(
                    f"Missing required PCI register fields: {missing_fields}")

            self.size: int = cfg_obj['size']
            self.offset: Union[int, str] = cfg_obj['offset']
            self.pci = pci_obj

            # Validate configuration
            if not self.validate_pci_register_config():
                raise PCIRegisterError("Invalid PCI register configuration")

        except Exception as e:
            if isinstance(e, (PCIRegisterError, CSConfigError)):
                raise
            raise PCIRegisterError(
                f"Error initializing PCI register: {str(e)}") from e

    def is_enabled(self) -> bool:
        """Check if the PCI register is enabled."""
        return self.pci.bus is not None

    def validate_pci_register_config(self) -> bool:
        """
        Validate PCI register-specific configuration.

        Returns:
            True if PCI register configuration is valid, False otherwise
        """
        try:
            # Validate size
            if not isinstance(self.size, int) or self.size <= 0:
                return False

            # Validate offset
            if isinstance(self.offset, str):
                try:
                    int(self.offset, 0)
                except ValueError:
                    return False
            elif not isinstance(self.offset, int):
                return False

            # Validate PCI object
            if self.pci is None:
                return False

            return True
        except Exception:
            return False

    def get_offset_int(self) -> int:
        """
        Get register offset as integer value.

        Returns:
            Offset as integer

        Raises:
            PCIRegisterError: If offset cannot be converted to integer
        """
        try:
            if isinstance(self.offset, int):
                return self.offset
            elif isinstance(self.offset, str):
                return int(self.offset, 0)
            else:
                raise PCIRegisterError(
                    f"Invalid offset type: {type(self.offset)}")
        except ValueError as e:
            raise PCIRegisterError(
                f"Cannot convert offset to integer: {self.offset}") from e

    def get_bdf_string(self) -> str:
        """
        Get Bus:Device:Function as formatted string.

        Returns:
            BDF string or 'Unknown' if PCI object is invalid
        """
        try:
            if self.pci and hasattr(self.pci, 'bus') and self.pci.bus is not None:
                bus = f'{self.pci.bus:02X}'
                dev = f'{self.pci.dev:02X}' if self.pci.dev is not None else 'XX'
                fun = f'{self.pci.fun:X}' if self.pci.fun is not None else 'X'
                return f'{bus}:{dev}.{fun}'
            return 'Unknown'
        except Exception:
            return 'Unknown'

    def get_register_summary(self) -> Dict[str, Any]:
        """
        Get summary of PCI register configuration.

        Returns:
            Dictionary with PCI register configuration summary
        """
        try:
            return {
                'name': self.name,
                'bdf': self.get_bdf_string(),
                'offset': self.get_offset_int(),
                'size': self.size,
                'desc': getattr(self, 'desc', None),
                'is_valid': self.validate_pci_register_config(),
                'has_value': self.value is not None
            }
        except Exception:
            return {
                'name': getattr(self, 'name', 'Unknown'),
                'bdf': 'Unknown',
                'offset': 0,
                'size': 0,
                'desc': None,
                'is_valid': False,
                'has_value': False
            }

    def __repr__(self) -> str:
        reg_str = ''
        if self.value is not None:
            reg_val_str = f'0x{self.value:0{self.size * 2}X}'
        else:
            reg_val_str = self.value
        b = f'{self.pci.bus:02x}' if self.pci.bus is not None else self.pci.bus
        d = f'{self.pci.dev:02x}' if self.pci.dev is not None else self.pci.dev
        f = f'{self.pci.fun:x}' if self.pci.fun is not None else self.pci.fun
        o = self.offset
        if self.default is not None:
            default = f'{self.default:X}'
        else:
            default = 'Not Provided'
        reg_str = f'[*] {self.name} = {reg_val_str} << {self.desc} (b:d.f {b}:{d}.{f} + 0x{o:X}) [default: {default}]'
        reg_str += self._register_fields_str(True)
        return reg_str

    def __str__(self) -> str:
        reg_str = ''
        if self.value is not None:
            reg_val_str = f'0x{self.value:0{self.size * 2}X}'
        else:
            reg_val_str = self.value
        
        b = f'{self.pci.bus:02x}' if self.pci.bus is not None else self.pci.bus
        d = f'{self.pci.dev:02x}' if self.pci.dev is not None else self.pci.dev
        f = f'{self.pci.fun:x}' if self.pci.fun is not None else self.pci.fun
        o = self.offset
        reg_str = f'[*] {self.name} = {reg_val_str} << {self.desc} (b:d.f {b}:{d}.{f} + 0x{o:X})'
        reg_str += self._register_fields_str()
        return reg_str

    def read(self):
        """Read the object"""
        self.logger.log_debug(f'reading {self.name}')
        _cs = cs()
        if self.pci.bus is not None:
            self.value = _cs.hals.Pci.read(self.pci.bus, self.pci.dev, self.pci.fun, self.offset, self.size)
        else:
            raise CSReadError(f'PCI Device is not available ({self.pci.bus}:{self.pci.dev}.{self.pci.fun})')
        return self.value

    def write(self, value):
        """Write the object"""
        _cs = cs()
        if self.pci.bus is not None:
            _cs.hals.Pci.write(self.pci.bus, self.pci.dev, self.pci.fun, self.offset, self.size, value)
        else:
            raise CSReadError(f'PCI Device is not available ({self.pci.bus}:{self.pci.dev}.{self.pci.fun})')
