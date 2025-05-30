# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2019-2021, Intel Corporation
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

__version__ = '1.2'

from typing import List, Optional, Tuple
from chipsec.library.defines import bit, is_set
from chipsec.hal.hal_base import HALBase
from chipsec.library.exceptions import CSReadError, HWAccessViolationError


class LockResult:
    DEFINED = bit(0)  # lock exists within configuration
    HAS_CONFIG = bit(1)  # lock configuration exists
    LOCKED = bit(2)  # lock matches value within xml
    CAN_READ = bit(3)  # system is able to access the lock
    INCONSISTENT = bit(4)  # all lock results do not match


class Locks(HALBase):
    def __init__(self, cs):
        super(Locks, self).__init__(cs)

    def get_locks(self) -> List[str]:
        """
        Return a list of locks defined within the configuration file
        """
        return self.cs.lock.get_list()

    def set_cache(self, lock_obj: "LOCKSHelper", reg_obj_list: List["RegisterHelper"]) -> None:
        """
        Set the cache for the lock and its associated registers.
        Arguments:
            lock_obj: The lock object containing the lock definition.
            reg_obj_list: A list of register objects associated with the lock.
        """
        self.lock_cache = lock_obj
        self.reg_cache = reg_obj_list

    def clear_cache(self) -> None:
        """
        Clear the cache for the lock and its associated registers.
        """
        self.lock_cache = None
        self.reg_cache = None

    def get_cache(self) -> Tuple[Optional["LOCKSHelper"], Optional[List["RegisterHelper"]]]:
        """
        Get the cached lock and register objects.
        Returns:
            A tuple containing the cached lock object and a list of register objects.
        """
        return (self.lock_cache, self.reg_cache)

    def read_lock(self) -> int:
        """
        Read the lock value from the cached register.
        Returns:
            The value of the lock field.
        """
        if self.lock_cache is None or self.reg_cache is None:
            raise CSReadError('Lock cache is not set')
        return self.reg_cache.read_field(self.lock_cache.field)

    def lock_valid(self, lock_name: str, instance: Optional["instance"] = None) -> int:
        """
        Validate the lock by its name and instance.
        Arguments:
            lock_name: The name of the lock to validate.
            instance: Optional instance to validate against.
        Returns:
            An integer representing the validation result, which can include:
            - LockResult.DEFINED: Lock is defined in the configuration.
            - LockResult.HAS_CONFIG: Lock has a configuration.
            - LockResult.CAN_READ: Lock can be read.
            - LockResult.INCONSISTENT: Lock values are inconsistent.
            - LockResult.LOCKED: Lock is locked with the expected value.
        """
        self.clear_cache()
        res = self.validate_lock_definition(lock_name)
        if not res:
            return res

        lock_obj = self.cs.lock.get(lock_name)

        reg_list = self.get_registers(lock_obj, instance)
        self.set_cache(lock_obj, reg_list)

        if not reg_list:
            self.logger.log_hal(f"Lock '{lock_name}' has no register defined")
            return res

        if not lock_obj.has_lock_value():
            self.logger.log_hal(f"Lock '{lock_name}' has no lock value defined")
            return res

        if not reg_list[0].has_field(lock_obj.get_field()):
            self.logger.log_hal(f"Lock '{lock_name}' has no field defined")
            return res

        res |= LockResult.HAS_CONFIG
        try:
            self.read_lock()
            res |= LockResult.CAN_READ
        except CSReadError as e:
            self.logger.log_hal(f"Error reading lock: {e}")
        except HWAccessViolationError as e:
            self.logger.log_hal(f"Hardware access violation: {e}")

        return res

    def is_locked(self, lock_name: str, bus: Optional[int] = None) -> int:
        """
        Return whether the lock has the value setting
        Arguments:
            lock_name: The name of the lock to check.
            bus: Optional bus number to specify the bus context.
        Returns:
            An integer representing the lock state, which can include:
            - LockResult.INCONSISTENT: Lock values are inconsistent.
            - LockResult.LOCKED: Lock is locked with the expected value.
        """
        res = self.lock_valid(lock_name, bus)
        if is_set(res, LockResult.HAS_CONFIG) and is_set(res, LockResult.CAN_READ):
            res |= self._is_lock_consistent()
            res |= self._check_lock_values()
        return res

    def _is_lock_consistent(self) -> int:
        """
        Check if the lock is consistent across all registers.
        Returns:
            An integer indicating the consistency of the lock.
            Returns LockResult.INCONSISTENT if the values are not consistent.
            Returns 0 if they are consistent.
        """
        lock_obj, reg_list = self.get_cache()
        lock_field = lock_obj.get_field()
        reg_list.read()
        if not reg_list.is_all_field_value(reg_list[0].get_field(lock_field), lock_field):
            return LockResult.INCONSISTENT
        return 0

    def _check_lock_values(self) -> int:
        """
        Check if all registers in the list have the same value for the specified field.
        Returns:
            An integer indicating the lock state.
            Returns LockResult.LOCKED if all registers have the expected value.
            Returns 0 if they do not match.
        """
        lock_obj, reg_list = self.get_cache()
        locked_value = lock_obj.lock_value
        reg_list.read()
        if reg_list.is_all_field_value(locked_value, lock_obj.get_field()):
            return LockResult.LOCKED
        return 0

    def validate_lock_definition(self, lock_name: str) -> int:
        """
        Validate if the lock is defined in the configuration file.
        Arguments:
            lock_name: The name of the lock to validate.
        Returns:
            An integer representing the validation result, which can include:
            - LockResult.DEFINED: Lock is defined in the configuration.
            - 0: Lock is not defined.
        """
        lock_obj = self.cs.lock.get(lock_name)
        if lock_obj is None:
            self.logger.log_hal(f"Lock '{lock_name}' is not defined in the configuration file")
            return 0
        return LockResult.DEFINED

    def get_registers(self, lock_obj, instance: Optional["instance"]) -> List:
        """
        Retrieve registers associated with the lock.
        Arguments:
            lock_obj: The lock object containing the lock definition.
            instance: Optional instance to filter the registers.
        Returns:
            A list of register objects associated with the lock.
            If an instance is provided, it returns the registers for that specific instance.
            If no instance is provided, it returns all registers associated with the lock.
        """
        lock_register = lock_obj.get_register()
        if instance:
            reg_obj = self.cs.register.get_instance_by_name(lock_register, instance)
            return list(reg_obj)
        return self.cs.register.get_list_by_name(lock_register)


haldata = {"arch": [HALBase.MfgIds.Any], 'name': ['Locks']}
