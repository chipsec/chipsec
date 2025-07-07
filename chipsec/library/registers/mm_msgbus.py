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
Memory-Mapped Message Bus register interface.

This module provides functionality to access and manage Memory-Mapped
Message Bus registers in the CHIPSEC framework.
"""

from typing import Any, Optional
from chipsec.library.registers.baseregister import BaseRegister


class MMMsgBus(BaseRegister):
    """
    Memory-Mapped Message Bus register interface.

    Provides methods to access and query MM Message Bus register definitions.
    """

    def __init__(self, cs: Any) -> None:
        """
        Initialize the MM Message Bus register interface.

        Args:
            cs: Chipset interface object
        """
        super(MMMsgBus, self).__init__(cs)

    def get_def(self, mmsgbus_name: str) -> Optional[Any]:
        """
        Get the definition of a MM Message Bus by name.

        Args:
            mmsgbus_name: Name of the MM Message Bus to retrieve

        Returns:
            MM Message Bus definition if found, None otherwise
        """
        scope = self.cs.Cfg.get_scope(mmsgbus_name)
        vid, device, mmbus, _ = self.cs.Cfg.convert_internal_scope(
            scope, mmsgbus_name)

        if (vid in self.cs.Cfg.MM_MSGBUS and
            device in self.cs.Cfg.MM_MSGBUS[vid] and
            mmbus in self.cs.Cfg.MM_MSGBUS[vid][device]):
            return self.cs.Cfg.MM_MSGBUS[vid][device][mmbus]

        return None
