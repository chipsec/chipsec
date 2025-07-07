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
PCI Configuration register interface.

This module provides functionality to access and manage PCI Configuration
registers in the CHIPSEC framework.
"""

from typing import Any, List, Optional
from chipsec.library.registers.baseregister import BaseRegister


class PCICfg(BaseRegister):
    """
    PCI Configuration register interface for PCI registers.

    Provides methods to access and query PCI Configuration register definitions.
    """

    def __init__(self, cs: Any) -> None:
        """
        Initialize the PCI Configuration register interface.

        Args:
            cs: Chipset interface object
        """
        super(PCICfg, self).__init__(cs)

    def get_def(self, device_name: str) -> Optional[Any]:
        """
        Get the definition of a PCI device by name.

        Args:
            device_name: Name of the PCI device to retrieve

        Returns:
            PCI device definition if found, None otherwise
        """
        scope = self.cs.Cfg.get_scope(device_name)
        vid, device, bar, _ = self.cs.Cfg.convert_internal_scope(
            scope, device_name)

        # Check if this is actually referencing an I/O BAR configuration
        # This appears to be a bug in the original implementation
        # Should be modified to use PCI_DEVICES dictionary instead
        if (vid in self.cs.Cfg.PCI_DEVICES and
            device in self.cs.Cfg.PCI_DEVICES[vid] and
            bar in self.cs.Cfg.PCI_DEVICES[vid][device]):
            return self.cs.Cfg.PCI_DEVICES[vid][device][bar]

        return None

    def get_match(self, pattern: str) -> List[str]:
        """
        Get PCI devices matching a specific pattern.

        Args:
            pattern: Pattern to match against PCI device names

        Returns:
            List of matching PCI device identifiers
        """
        scope = self.cs.Cfg.get_scope(pattern)
        vid, device, bar, _ = self.cs.Cfg.convert_internal_scope(scope, pattern)
        ret = []

        if vid is None or vid == '*':
            vid_list = list(self.cs.Cfg.PCI_DEVICES.keys())
        else:
            vid_list = [vid]

        for v in vid_list:
            if v in self.cs.Cfg.PCI_DEVICES:
                if device is None or device == '*':
                    dev_list = list(self.cs.Cfg.PCI_DEVICES[v].keys())
                else:
                    dev_list = [device]

                for d in dev_list:
                    if d in self.cs.Cfg.PCI_DEVICES[v]:
                        if bar is None or bar == '*':
                            bar_list = list(self.cs.Cfg.PCI_DEVICES[v][d].keys())
                        else:
                            bar_list = [bar]

                        for b in bar_list:
                            if b in self.cs.Cfg.PCI_DEVICES[v][d]:
                                ret.append(f'{v}.{d}.{b}')

        return ret
