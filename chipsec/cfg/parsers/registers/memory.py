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

from chipsec.library.exceptions import CSConfigError
from chipsec.library.register import BaseConfigRegisterHelper
from chipsec.chipset import cs


class MEMORYRegisters(BaseConfigRegisterHelper):
    def __init__(self, cfg_obj):
        super(MEMORYRegisters, self).__init__(cfg_obj)
        self.offset = cfg_obj['offset']
        self.range = cfg_obj['range']
        self.size = cfg_obj['size']
        self.address = cfg_obj['address']
        self.limit = cfg_obj['limit']
        self.access = cfg_obj['access']

    def __repr__(self) -> str:
        reg_str = ''
        if self.value is not None:
            reg_val_str = f'0x{self.value:08X}'
        else:
            reg_val_str = self.value
        if self.default is not None:
            default = f'{self.default:X}'
        else:
            default = 'Not Provided'
        reg_str = f'[*] {self.name} = {reg_val_str} << {self.desc} (0x{self.address:X} + 0x{self.offset:X}) [default: {default}]'

        reg_str += self._register_fields_str(True)
        return reg_str

    def __str__(self) -> str:
        reg_str = ''
        if self.value is not None:
            reg_val_str = f'0x{self.value:08X}'
        else:
            reg_val_str = self.value

        reg_str = f'[*] {self.name} = {reg_val_str} << {self.desc} (0x{self.address:X} + 0x{self.offset:X})'

        reg_str += self._register_fields_str()
        return reg_str

    def read(self):
        """Read the object"""
        self.logger.log_debug(f'reading {self.name}')
        _cs = cs()
        if self.access == 'dram':
            self.value = _cs.hals.MemRange.read(self.address + self.offset, self.size)
        elif self.access == 'mmio':
            self.value = _cs.hals.MMIO.read_MMIO_reg(self.address, self.offset, self.size)
        return self.value

    def write(self, value):
        """Write the object"""
        _cs = cs()
        if self.access == 'dram':
            _cs = _cs.hals.Memory.write_physical_mem(self.address + self.offset, self.size, value)
        elif self.access == 'mmio':
            _cs.hals.MMIO.write_MMIO_reg(self.address, self.offset, value, self.size, None)
