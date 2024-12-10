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

from chipsec.library.register import BaseConfigRegisterHelper
from chipsec.chipset import cs


class IOBARRegisters(BaseConfigRegisterHelper):
    def __init__(self, cfg_obj):
        super(IOBARRegisters, self).__init__(cfg_obj)
        self.size = cfg_obj['size']
        self.offset = cfg_obj['offset']
        self.bar = cfg_obj['bar']
        self.bar_base = None
        self.bar_size = None
        self.io_port = None

    def __repr__(self) -> str:
        reg_str = ''
        if self.value is not None:
            reg_val_str = '0x{self.value:0{self.size * 2}X}'
        else:
            reg_val_str = self.value
        instance = f'{self.instance}' if self.instance is not None else 'Fixed'
        if self.default is not None:
            default = f'{self.default:X}'
        else:
            default = 'Not Provided'
        reg_str = f'[*] {self.name} = {reg_val_str} << {self.desc} ({self.bar} + 0x{self.offset:X} Bus {instance}) [default: {default}]'

        reg_str += self._register_fields_str(True)
        return reg_str

    def __str__(self) -> str:
        reg_str = ''
        if self.value is not None:
            reg_val_str = '0x{self.value:0{self.size * 2}X}'
        else:
            reg_val_str = self.value

        instance = f'{self.instance}' if self.instance is not None else 'Fixed'
        reg_str = f'[*] {self.name} = {reg_val_str} << {self.desc} ({self.bar} + 0x{self.offset:X} Bus {instance})'

        reg_str += self._register_fields_str()
        return reg_str

    def read(self):
        """Read the object"""
        self.logger.log_debug(f'reading {self.name}')
        _cs = cs()
        if self.io_port is None:
            (self.bar_base, self.bar_size) = _cs.hals.PortIObar.get_IO_BAR_base_address(self.bar, self.instance)
            self.io_port = self.bar_base + self.offset
        self.value = _cs.hals.Io.read(self.io_port, self.size)
        self.logger.log_debug('done reading')
        return self.value

    def write(self, value):
        """Write the object"""
        _cs = cs()
        if self.io_port is None:
            (self.bar_base, self.bar_size) = _cs.hals.PortIObar.get_IO_BAR_base_address(self.bar, self.instance.instance)
            self.io_port = self.bar_base + self.offset
        _cs.hals.Io.write(self.io_port, value, self.size)
