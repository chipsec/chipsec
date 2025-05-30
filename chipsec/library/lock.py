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
from typing import List, Optional, Set


class Lock:
    def __init__(self, cs):
        self.cs = cs

    def get(self, lock_name: str) -> Optional['LOCKSHelper']:
        """Retrieves the lock object associated with the lock_name."""
        if lock_name in self.cs.Cfg.LOCKS:
            return self.cs.Cfg.LOCKS[lock_name]
        else:
            logger().log(f'Lock {lock_name} is not defined in the configuration file')
            return None

    def get_list(self) -> List[str]:
        """Retrieve a list of locks that are currently loaded from config files."""
        return list(self.cs.Cfg.LOCKS.keys())

    def get_lockedby(self, lock_name: str) -> Optional[List[Set[str]]]:
        """Retrieve a list of registers locked by lock_name."""
        vid, _, _, _ = self.cs.Cfg.convert_internal_scope("", lock_name)
        if lock_name in self.cs.Cfg.LOCKEDBY[vid]:
            return self.cs.Cfg.LOCKEDBY[vid][lock_name]
        else:
            return None
