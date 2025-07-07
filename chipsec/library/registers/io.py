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
I/O register interface.

This module provides functionality to access and manage I/O port registers
in the CHIPSEC framework.
"""

from typing import Any, List, Optional
from chipsec.library.registers.baseregister import BaseRegister


class IO(BaseRegister):
    """
    I/O register interface for I/O port registers.

    Provides methods to access and query I/O register definitions.
    """

    def __init__(self, cs: Any) -> None:
        """
        Initialize the I/O register interface.

        Args:
            cs: Chipset interface object
        """
        super(IO, self).__init__(cs)

    def get_def(self, bar_name: str) -> Optional[Any]:
        """
        Get the definition of an I/O BAR by name.

        Args:
            bar_name: Name of the I/O BAR to retrieve

        Returns:
            I/O BAR definition if found, None otherwise
        """
        scope = self.cs.Cfg.get_scope(bar_name)
        vid, device, bar, _ = self.cs.Cfg.convert_internal_scope(
            scope, bar_name)

        if (vid in self.cs.Cfg.IO_BARS and
            device in self.cs.Cfg.IO_BARS[vid] and
            bar in self.cs.Cfg.IO_BARS[vid][device]):
            return self.cs.Cfg.IO_BARS[vid][device][bar]

        return None

    def get_match(self, pattern: str) -> List[str]:
        """
        Get I/O BARs matching a specific pattern.

        Args:
            pattern: Pattern to match against I/O BAR names

        Returns:
            List of matching I/O BAR identifiers
        """
        scope = self.cs.Cfg.get_scope(pattern)
        vid, device, bar, _ = self.cs.Cfg.convert_internal_scope(scope, pattern)
        ret = []

        if vid is None or vid == '*':
            vid_list = list(self.cs.Cfg.IO_BARS.keys())
        else:
            vid_list = [vid]

        for v in vid_list:
            if v in self.cs.Cfg.IO_BARS:
                if device is None or device == '*':
                    dev_list = list(self.cs.Cfg.IO_BARS[v].keys())
                else:
                    dev_list = [device]

                for d in dev_list:
                    if d in self.cs.Cfg.IO_BARS[v]:
                        if bar is None or bar == '*':
                            bar_list = list(self.cs.Cfg.IO_BARS[v][d].keys())
                        else:
                            bar_list = [bar]

                        for b in bar_list:
                            if b in self.cs.Cfg.IO_BARS[v][d]:
                                ret.append(f'{v}.{d}.{b}')

        return ret
