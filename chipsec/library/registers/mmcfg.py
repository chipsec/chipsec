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

'''
Main functionality to get the definition of IO registers
'''
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
MMCFG (Memory-Mapped PCI Configuration) register interface.

This module provides functionality to access and manage MMCFG registers
in the CHIPSEC framework.
"""

from typing import Any, List, Optional
from chipsec.library.registers.baseregister import BaseRegister


class MMCfg(BaseRegister):
    """
    MMCFG register interface.

    Provides methods to access and query MMCFG register definitions.
    """

    def __init__(self, cs: Any) -> None:
        """
        Initialize the MMCFG register interface.

        Args:
            cs: Chipset interface object
        """
        super(MMCfg, self).__init__(cs)

    def get_def(self, mmcfg_name: str) -> Optional[Any]:
        """
        Get the definition of an MMCFG BAR by name.

        Args:
            mmcfg_name: Name of the MMCFG BAR to retrieve

        Returns:
            MMCFG BAR definition if found, None otherwise
        """
        scope = self.cs.Cfg.get_scope(mmcfg_name)
        vid, device, mmcfg, _ = self.cs.Cfg.convert_internal_scope(
            scope, mmcfg_name)

        if (vid in self.cs.Cfg.MMCFG_BARS and
            device in self.cs.Cfg.MMCFG_BARS[vid] and
            mmcfg in self.cs.Cfg.MMCFG_BARS[vid][device]):
            return self.cs.Cfg.MMCFG_BARS[vid][device][mmcfg]

        return None

    def get_match(self, pattern: str) -> List[str]:
        """
        Get MMCFG BARs matching a specific pattern.

        Args:
            pattern: Pattern to match against MMCFG BAR names

        Returns:
            List of matching MMCFG BAR identifiers
        """
        scope = self.cs.Cfg.get_scope(pattern)
        vid, device, mmcfg, _ = self.cs.Cfg.convert_internal_scope(scope, pattern)
        ret = []

        if vid is None or vid == '*':
            vid_list = list(self.cs.Cfg.MMCFG_BARS.keys())
        else:
            vid_list = [vid]

        for v in vid_list:
            if v in self.cs.Cfg.MMCFG_BARS:
                if device is None or device == '*':
                    dev_list = list(self.cs.Cfg.MMCFG_BARS[v].keys())
                else:
                    dev_list = [device]

                for d in dev_list:
                    if d in self.cs.Cfg.MMCFG_BARS[v]:
                        if mmcfg is None or mmcfg == '*':
                            mmcfg_list = list(self.cs.Cfg.MMCFG_BARS[v][d].keys())
                        else:
                            mmcfg_list = [mmcfg]

                        for m in mmcfg_list:
                            if m in self.cs.Cfg.MMCFG_BARS[v][d]:
                                ret.append(f'{v}.{d}.{m}')

        return ret

from chipsec.library.registers.baseregister import BaseRegister

class MMCfg(BaseRegister):
    def __init__(self, cs):
        super(MMCfg, self).__init__(cs)

    def get_def(self, bar_name):
        scope = self.cs.Cfg.get_scope(bar_name)
        vid, device, bar, _ = self.cs.Cfg.convert_internal_scope(scope, bar_name)
        if bar in self.cs.Cfg.IO_BARS[vid][device]:
            return self.cs.Cfg.IO_BARS[vid][device][bar]
        else:
            return None
