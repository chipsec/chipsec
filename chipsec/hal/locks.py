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

__version__ = '1.0'

from typing import List, Optional
from chipsec.library.defines import bit, is_set
from chipsec.hal.hal_base import HALBase
from chipsec.library.exceptions import CSReadError, HWAccessViolationError


class LockResult:
    DEFINED = bit(0)  # lock exists within configuration
    HAS_CONFIG = bit(1)  # lock configuration exists
    LOCKED = bit(2)  # lock matches value within xml
    CAN_READ = bit(3)  # system is able to access the lock
    INCONSISTENT = bit(4)  # all lock results do not match


class locks(HALBase):
    def __init__(self, cs):
        super(locks, self).__init__(cs)

    def get_locks(self) -> List[str]:
        """
        Return a list of locks defined within the configuration file
        """
        return self.cs.lock.get_list()

    def lock_valid(self, lock_name: str, bus: Optional[int] = None) -> int:
        res = 0
        if self.cs.lock.is_defined(lock_name):
            res |= LockResult.DEFINED
        try:
            self.cs.get_locked_value(lock_name)
            self.cs.lock.get(lock_name, bus=bus)
            res |= LockResult.HAS_CONFIG
            res |= LockResult.CAN_READ
        except KeyError:
            pass
        except CSReadError:
            res |= LockResult.HAS_CONFIG
        except HWAccessViolationError:
            res |= LockResult.HAS_CONFIG
        return res

    def is_locked(self, lock_name: str, bus: Optional[int] = None) -> int:
        """
        Return whether the lock has the value setting
        """
        res = self.lock_valid(lock_name, bus)
        if is_set(res, LockResult.HAS_CONFIG) and is_set(res, LockResult.CAN_READ):
            locked = self.cs.get_locked_value(lock_name)
            lock_setting = self.cs.lock.get(lock_name, bus=bus)
            if not all(lock_setting[0] == elem for elem in lock_setting):
                res |= LockResult.INCONSISTENT
            if all(locked == elem for elem in lock_setting):
                res |= LockResult.LOCKED
        return res
