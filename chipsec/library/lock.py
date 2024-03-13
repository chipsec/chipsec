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
from typing import List, Optional, Set, Union

class Lock:
    def __init__(self, cs):
        self.cs = cs

    def get(self, lock_name: str, cpu_thread: int=0, with_print: bool=False, bus: Optional[int]=None) -> Union[int, List[int]]:
        '''Retrieves information for the lock associated with the register/field by lock_name.'''
        lock = self.cs.Cfg.LOCKS[lock_name]
        reg = lock['register']
        field = lock['field']
        if bus is None:
            reg_data = self.cs.register.read_all(reg, cpu_thread)
        else:
            reg_data = self.cs.register.read(reg, cpu_thread, bus)
            reg_data = [reg_data]
        if logger().VERBOSE or with_print:
            if reg_data:
                for rd in reg_data:
                    self.cs.register.print(reg, rd)
            else:
                logger().log('Register has no data')
        if reg_data:
            return self.cs.register.get_field_all(reg, reg_data, field)
        return reg_data

    def set(self, lock_name: str, lock_value: int, cpu_thread: int=0, bus: Optional[int]=None) -> bool:
        '''Sets the value of a lock associated with the given lock_name.'''
        lock = self.cs.Cfg.LOCKS[lock_name]
        reg = lock['register']
        field = lock['field']
        if bus is None:
            reg_data = self.cs.register.read_all(reg, cpu_thread)
            reg_data = self.cs.register.set_field_all(reg, reg_data, field, lock_value)
            return self.cs.register.write_all(reg, reg_data, cpu_thread)
        else:
            reg_data = self.cs.register.read(reg, cpu_thread, bus)
            reg_data = self.cs.register.set_field(reg, reg_data, field, lock_value)
            return self.cs.register.write(reg, reg_data, cpu_thread, bus)

    def is_defined(self, lock_name: str) -> bool:
        '''Checks if lock is defined in the XML config'''
        return lock_name in self.cs.Cfg.LOCKS.keys()

    def get_value(self, lock_name: str) -> int:
        '''Retrieves the expected value of a lock associated with the lock_name.'''
        if logger().DEBUG:
            logger().log(f'Retrieve value for lock {lock_name}')
        return self.cs.Cfg.LOCKS[lock_name]['value']

    def get_desc(self, lock_name: str) -> str:
        '''Retrieves the description of a lock assoicated with the lock_name.'''
        return self.cs.Cfg.LOCKS[lock_name]['desc']

    def get_type(self, lock_name: str) -> str:
        '''Fetcheth the type of a register associated with the lock_name.'''
        if 'type' in self.cs.Cfg.LOCKS[lock_name].keys():
            mtype = self.cs.Cfg.LOCKS[lock_name]['type']
        else:
            mtype = 'RW/L'
        return mtype

    def get_list(self) -> List[str]:
        '''Retrieve a list of locks that are currently loaded from config files.'''
        return list(self.cs.Cfg.LOCKS.keys())

    def get_mask(self, lock_name: str) -> int:
        '''Retrieve the field mask of a register associated with the lock_name.'''
        lock = self.cs.Cfg.LOCKS[lock_name]
        reg = lock['register']
        field = lock['field']
        return self.cs.register.get_field_mask(reg, field)

    def get_lockedby(self, lock_name: str) -> Optional[List[Set[str]]]:
        '''Retrieve a list of registers locked by lock_name.'''
        if lock_name in self.cs.Cfg.LOCKEDBY.keys():
            return self.cs.Cfg.LOCKEDBY[lock_name]
        else:
            return None
