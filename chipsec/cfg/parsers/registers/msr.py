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


class MSRRegisters(BaseConfigRegisterHelper):
    def __init__(self, cfg_obj):
        super(MSRRegisters, self).__init__(cfg_obj)
        if 'size' in cfg_obj:
            self.size = cfg_obj['size']
        else:
            self.size = 8
        self.thread = cfg_obj['instance']
        self.msr = cfg_obj['msr']

    def __repr__(self) -> str:
        reg_str = ''
        if self.value is not None:
            reg_val_str = f'0x{self.value:0{self.size * 2}X}'
        else:
            reg_val_str = self.value
        if self.default is not None:
            default = f'{self.default:X}'
        else:
            default = 'Not Provided'
        reg_str = f'[*] {self.name} = {reg_val_str} << {self.desc} (MSR 0x{self.msr:X} Thread 0x{self.thread:X}) [default: {default}]'

        reg_str += self._register_fields_str(True)
        return reg_str

    def __str__(self) -> str:
        reg_str = ''
        if self.value is not None:
            reg_val_str = f'0x{self.value:0{self.size * 2}X}'
        else:
            reg_val_str = self.value

        reg_str = f'[*] {self.name} = {reg_val_str} << {self.desc} (MSR 0x{self.msr:X} Thread 0x{self.thread:X})'

        reg_str += self._register_fields_str()
        return reg_str

    def read(self):
        """Read the object"""
        self.logger.log_debug(f'reading {self.name}')
        _cs = cs()
        (eax, edx) = _cs.hals.Msr.read_msr(self.thread, self.msr)
        self.value = (edx << 32) | eax
        return self.value

    def write(self, value):
        """Write the object"""
        _cs = cs()
        eax = value & 0xFFFFFFFF
        edx = (value >> 32) & 0xFFFFFFFF
        _cs.hals.Msr.write(self.thread, self.msr, eax, edx)
