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
Control interface module.

This module provides functionality to access and manage platform control
definitions in the CHIPSEC framework.
"""

from typing import Any, List, Optional
from chipsec.library.register import ObjList


class Control:
    """
    Control interface for platform control definitions.

    Provides methods to access and query control objects that define
    platform-specific control mechanisms.
    """

    def __init__(self, cs: Any) -> None:
        """
        Initialize the Control interface.

        Args:
            cs: Chipset interface object
        """
        self.cs = cs

    def get_list_by_name(self, control_name: str) -> ObjList:
        """
        Get list of control objects by name.

        Args:
            control_name: Name of the control to retrieve objects for

        Returns:
            List of control objects matching the name
        """
        controls = ObjList()
        if control_name in self.cs.Cfg.CONTROLS:
            controls.extend(self.cs.Cfg.CONTROLS[control_name])
        return controls

    def get_instance_by_name(self, control_name: str, instance: Any) -> Optional[Any]:
        """
        Get a specific control instance by name and instance identifier.

        Args:
            control_name: Name of the control
            instance: Instance identifier to retrieve

        Returns:
            Control instance if found, None otherwise
        """
        if control_name in self.cs.Cfg.CONTROLS:
            for ctrl in self.cs.Cfg.CONTROLS[control_name]:
                if instance == ctrl.instance:
                    return ctrl
        return None

    def get_def(self, control_name: str) -> List[Any]:
        """
        Get control definition by name.

        Args:
            control_name: Name of the control to retrieve

        Returns:
            List of control definitions

        Raises:
            KeyError: If control_name is not found in configuration
        """
        return self.cs.Cfg.CONTROLS[control_name]

    def is_defined(self, control_name: str) -> bool:
        """
        Check if a control name is defined.

        Args:
            control_name: Name of the control to check

        Returns:
            True if control is defined, False otherwise
        """
        return control_name in self.cs.Cfg.CONTROLS
