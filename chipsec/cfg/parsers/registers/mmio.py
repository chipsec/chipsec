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
from chipsec.library.exceptions import CSReadError, CSConfigError


class MMIORegisters(BaseConfigRegisterHelper):
    def __init__(self, cfg_obj):
        super(MMIORegisters, self).__init__(cfg_obj)
        self.cs = cs()
        self.size = cfg_obj['size']
        self.offset = cfg_obj['offset']
        self.bar_base = None
        self.bar_size = None
        self.bar = None
        self.range = None
        if 'bar' in cfg_obj:
            self.bar = cfg_obj['bar']
        elif 'range' in cfg_obj:
            self.range = cfg_obj['range']
            

    def __repr__(self) -> str:
        reg_str = ''
        if self.value is not None:
            reg_val_str = f'0x{self.value:0{self.size * 2}X}'
        else:
            reg_val_str = self.value
        instance = f'{self.instance}' if self.instance is not None else 'Fixed'
        if self.default is not None:
            default = f'{self.default:X}'
        else:
            default = 'Not Provided'
        reg_str = f'[*] {self.name} = {reg_val_str} << {self.desc} ({self.bar} + 0x{self.offset:X} {instance}) [default: {default}]'

        reg_str += self._register_fields_str(True)
        return reg_str

    def __str__(self) -> str:
        reg_str = ''
        if self.value is not None:
            reg_val_str = f'0x{self.value:0{self.size * 2}X}'
        else:
            reg_val_str = self.value

        instance = f'{self.instance}' if self.instance is not None else 'Fixed'
        reg_str = f'[*] {self.name} = {reg_val_str} << {self.desc} ({self.bar} + 0x{self.offset:X} {instance})'

        reg_str += self._register_fields_str()
        return reg_str

    def populate_base_address(self):
        if self.bar_base is None:
            if self.bar:
                (self.bar_base, self.bar_size) = self.cs.hals.MMIO.get_MMIO_BAR_base_address(self.bar, self.instance)
            elif self.range:
                mem_range_def = self.cs.hals.MemRange.get_def(self.range)
                if mem_range_def:
                    if mem_range_def.access == 'mmio':
                        self.bar_size = mem_range_def.size
                        self.bar_base = mem_range_def.address
                    else:
                        raise CSConfigError(f"Memory Range ({self.range}) access type ({mem_range_def.access}) is not MMIO.")
                else:
                    raise CSConfigError(f"Memory Range ({self.range}) cannot be found.")
            else:
                raise CSConfigError(f"Unable to populate MMIO Base Address: {self.name}")

    def read(self):
        """Read the object"""
        self.logger.log_debug(f'reading {self.name}')
        self.populate_base_address()
        self.value = self.cs.hals.MMIO.read_MMIO_reg(self.bar_base, self.offset, self.size, self.bar_size)
        self.logger.log_debug('done reading')
        return self.value

    def write(self, value):
        """Write the object"""
        self.populate_base_address()
        self.cs.hals.MMIO.write_MMIO_reg(self.bar_base, self.offset, value, self.size, self.bar_size)

    def write_subset(self, value, size, offset=0):
        if offset < self.size and size <= self.size - offset:
            self.populate_base_address()
            self.cs.hals.MMIO.write_MMIO_reg(self.bar_base, self.offset + offset, value, size, self.bar_size)
        else:
            raise CSReadError(f"Improper Offset or Size requested in write subset for {self.name}")
