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

from chipsec.chipset import cs
from chipsec.library.register import BaseConfigRegisterHelper
from chipsec.library.exceptions import CSReadError


class PCIRegisters(BaseConfigRegisterHelper):
    def __init__(self, cfg_obj, pci_obj):
        super(PCIRegisters, self).__init__(cfg_obj)
        self.size = cfg_obj['size']
        self.offset = cfg_obj['offset']
        self.pci = pci_obj

    def __repr__(self) -> str:
        reg_str = ''
        if self.value is not None:
            reg_val_str = f'0x{self.value:0{self.size * 2}X}'
        else:
            reg_val_str = self.value
        if self.pci.bus is not None:
            b = f'{self.pci.bus:02d}'
        else:
            b = self.pci.bus
        d = self.pci.dev
        f = self.pci.fun
        o = self.offset
        if self.default is not None:
            default = f'{self.default:X}'
        else:
            default = 'Not Provided'
        reg_str = f'[*] {self.name} = {reg_val_str} << {self.desc} (b:d.f {b}:{d:02d}.{f:d} + 0x{o:X}) [default: {default}]'
        reg_str += self._register_fields_str(True)
        return reg_str

    def __str__(self) -> str:
        reg_str = ''
        if self.value is not None:
            reg_val_str = f'0x{self.value:0{self.size * 2}X}'
        else:
            reg_val_str = self.value
        if self.pci.bus is not None:
            b = f'{self.pci.bus:02d}'
        else:
            b = self.pci.bus
        d = self.pci.dev
        f = self.pci.fun
        o = self.offset
        reg_str = f'[*] {self.name} = {reg_val_str} << {self.desc} (b:d.f {b}:{d:02d}.{f:d} + 0x{o:X})'
        reg_str += self._register_fields_str()
        return reg_str

    def read(self):
        """Read the object"""
        self.logger.log_debug(f'reading {self.name}')
        _cs = cs()
        if self.pci.bus is not None:
            self.value = _cs.pci.read(self.pci.bus, self.pci.dev, self.pci.fun, self.offset, self.size)
        else:
            raise CSReadError(f'PCI Device is not available ({self.pci.bus}:{self.pci.dev}.{self.pci.fun})')
        return self.value

    def write(self, value):
        """Write the object"""
        _cs = cs()
        if self.pci.bus is not None:
            _cs.pci.write(self.pci.bus, self.pci.dev, self.pci.fun, self.offset, self.size, value)
        else:
            raise CSReadError(f'PCI Device is not available ({self.pci.bus}:{self.pci.dev}.{self.pci.fun})')
