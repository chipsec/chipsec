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
Model-Specific Register (MSR) interface.

This module provides functionality to access and manage MSRs
in the CHIPSEC framework.
"""

from typing import Any, List, Optional
from chipsec.library.registers.baseregister import BaseRegister


class MSR(BaseRegister):
    """
    MSR interface for Model-Specific Registers.

    Provides methods to access and query MSR definitions.
    """

    def __init__(self, cs: Any) -> None:
        """
        Initialize the MSR interface.

        Args:
            cs: Chipset interface object
        """
        super(MSR, self).__init__(cs)

    def get_def(self, msr_name: str) -> Optional[Any]:
        """
        Get the definition of an MSR by name.

        Args:
            msr_name: Name of the MSR to retrieve

        Returns:
            MSR definition if found, None otherwise
        """
        scope = self.cs.Cfg.get_scope(msr_name)
        vid, device, msr, _ = self.cs.Cfg.convert_internal_scope(
            scope, msr_name)

        if (vid in self.cs.Cfg.MSR and
            device in self.cs.Cfg.MSR[vid] and
            msr in self.cs.Cfg.MSR[vid][device]):
            return self.cs.Cfg.MSR[vid][device][msr]

        return None

    def get_match(self, pattern: str) -> List[str]:
        """
        Get MSRs matching a specific pattern.

        Args:
            pattern: Pattern to match against MSR names

        Returns:
            List of matching MSR identifiers
        """
        scope = self.cs.Cfg.get_scope(pattern)
        vid, device, msr, _ = self.cs.Cfg.convert_internal_scope(scope, pattern)
        ret = []

        if vid is None or vid == '*':
            vid_list = list(self.cs.Cfg.MSR.keys())
        else:
            vid_list = [vid]

        for v in vid_list:
            if v in self.cs.Cfg.MSR:
                if device is None or device == '*':
                    dev_list = list(self.cs.Cfg.MSR[v].keys())
                else:
                    dev_list = [device]

                for d in dev_list:
                    if d in self.cs.Cfg.MSR[v]:
                        if msr is None or msr == '*':
                            msr_list = list(self.cs.Cfg.MSR[v][d].keys())
                        else:
                            msr_list = [msr]

                        for m in msr_list:
                            if m in self.cs.Cfg.MSR[v][d]:
                                ret.append(f'{v}.{d}.{m}')

        return ret
