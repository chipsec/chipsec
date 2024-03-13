# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2024, Intel Corporation
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
#

from chipsec.library.logger import logger
class Control:
    def __init__(self, cs) -> None:
        self.cs = cs

    def get(self, control_name: str, cpu_thread: int=0, with_print: bool=False) -> int:
        '''Reads some control field (by name)'''
        control = self.cs.Cfg.CONTROLS[control_name]
        reg = control['register']
        field = control['field']
        reg_data = self.cs.register.read(reg, cpu_thread)
        if logger().VERBOSE or with_print:
            self.cs.register.print(reg, reg_data)
        return self.cs.register.get_field(reg, reg_data, field)

    def set(self, control_name: str, control_value: int, cpu_thread: int=0) -> bool:
        '''Writes some control field (by name)'''
        control = self.cs.Cfg.CONTROLS[control_name]
        reg = control['register']
        field = control['field']
        return self.cs.register.write_field(reg, field, control_value, cpu_thread=cpu_thread)

    def is_defined(self, control_name:str) -> bool:
        '''Returns True if control_name Control is defined.'''
        try:
            return (self.cs.Cfg.CONTROLS[control_name] is not None)
        except KeyError:
            return False

    def is_all_ffs(self, control_name: str, cpu_thread: int=0, field_only: bool=False) -> bool:
        '''Returns True if control_name Control value is all 0xFFs (all 1's)'''
        if self.is_defined(control_name) is None:
            if logger().DEBUG:
                logger().log_error(f"Control '{control_name}' not defined.")
            return True
        control = self.cs.Cfg.CONTROLS[control_name]
        reg_def = control['register']
        reg_data = self.cs.register.read(reg_def, cpu_thread)
        if field_only:
            reg_field = control['field']
            reg_data = self.cs.register.get_field(reg_def, reg_data, reg_field)
            result = self.cs.register.is_field_all_ones(reg_def, reg_field, reg_data)
        else:
            result = self.cs.register.is_all_ffs(reg_def, reg_data)
        return result
