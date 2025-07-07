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
Memory range register interface.

This module provides functionality to access and manage memory range definitions
in the CHIPSEC framework.
"""

from typing import Any, List, Optional
from chipsec.library.registers.baseregister import BaseRegister


class Memory(BaseRegister):
    """
    Memory range register interface.

    Provides methods to access and query memory range definitions.
    """

    def __init__(self, cs: Any) -> None:
        """
        Initialize the memory range register interface.

        Args:
            cs: Chipset interface object
        """
        super(Memory, self).__init__(cs)

    def get_def(self, range_name: str) -> Optional[Any]:
        """
        Get the definition of a memory range by name.

        Args:
            range_name: Name of the memory range to retrieve

        Returns:
            Memory range definition if found, None otherwise
        """
        scope = self.cs.Cfg.get_scope(range_name)
        vid, range_id, _, _ = self.cs.Cfg.convert_internal_scope(
            scope, range_name)

        if (vid in self.cs.Cfg.MEMORY_RANGES and
            range_id in self.cs.Cfg.MEMORY_RANGES[vid]):
            return self.cs.Cfg.MEMORY_RANGES[vid][range_id]

        return None

    def get_match(self, pattern: str) -> List[str]:
        """
        Get memory ranges matching a specific pattern.

        Args:
            pattern: Pattern to match against memory range names

        Returns:
            List of matching memory range identifiers
        """
        scope = self.cs.Cfg.get_scope(pattern)
        vid, range_id, _, _ = self.cs.Cfg.convert_internal_scope(scope, pattern)
        ret = []

        if vid is None or vid == '*':
            vid_list = list(self.cs.Cfg.MEMORY_RANGES.keys())
        else:
            vid_list = [vid]

        for v in vid_list:
            if v in self.cs.Cfg.MEMORY_RANGES:
                if range_id is None or range_id == '*':
                    range_list = list(self.cs.Cfg.MEMORY_RANGES[v].keys())
                else:
                    range_list = [range_id]

                for r in range_list:
                    if r in self.cs.Cfg.MEMORY_RANGES[v]:
                        ret.append(f'{v}.{r}')

        return ret
