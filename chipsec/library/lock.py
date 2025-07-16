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


"""
Lock interface module.

This module provides functionality to access and manage platform lock
definitions in the CHIPSEC framework.
"""

from typing import Any, List, Optional, Set
from chipsec.library.logger import logger


class Lock:
    """
    Lock interface for platform lock definitions.

    Provides methods to access and query lock objects that define
    platform-specific security lock mechanisms.
    """

    def __init__(self, cs: Any) -> None:
        """
        Initialize the Lock interface.

        Args:
            cs: Chipset interface object
        """
        self.cs = cs

    def get(self, lock_name: str) -> Optional[Any]:
        """
        Retrieve the lock object associated with the lock_name.

        Args:
            lock_name: Name of the lock to retrieve

        Returns:
            Lock object if found, None otherwise
        """
        if lock_name in self.cs.Cfg.LOCKS:
            return self.cs.Cfg.LOCKS[lock_name]
        else:
            logger().log(f'Lock {lock_name} is not defined in the '
                         'configuration file')
            return None

    def get_list(self) -> List[str]:
        """
        Retrieve a list of locks that are currently loaded from config files.

        Returns:
            List of lock names currently defined
        """
        return list(self.cs.Cfg.LOCKS.keys())

    def get_lockedby(self, lock_name: str) -> Optional[List[Set[str]]]:
        """
        Retrieve a list of registers locked by lock_name.

        Args:
            lock_name: Name of the lock

        Returns:
            List of register sets locked by the specified lock,
            None if lock is not found
        """
        vid, _, _, _ = self.cs.Cfg.convert_internal_scope("", lock_name)
        if (vid in self.cs.Cfg.LOCKEDBY and
                lock_name in self.cs.Cfg.LOCKEDBY[vid]):
            return self.cs.Cfg.LOCKEDBY[vid][lock_name]
        else:
            return None
