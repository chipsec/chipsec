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
Abstract base register class for register interfaces.

This module provides the BaseRegister class which serves as a parent class
for all register type interfaces in CHIPSEC.
"""

from typing import Any, Optional, List
from chipsec.library.exceptions import UnimplementedAPIError


class BaseRegister:
    """
    Base abstract class for register interfaces.

    Provides a common interface for all register types in CHIPSEC.
    Subclasses must implement the required methods.
    """

    def __init__(self, cs: Any) -> None:
        """
        Initialize the base register interface.

        Args:
            cs: Chipset interface object
        """
        self.cs = cs

    def get_def(self, reg_name: str) -> Optional[Any]:
        """
        Get the definition of a register by name.

        This is an abstract method that must be implemented by subclasses.

        Args:
            reg_name: Name of the register to retrieve

        Returns:
            Register definition object if found, None otherwise

        Raises:
            UnimplementedAPIError: If the subclass does not implement this method
        """
        raise UnimplementedAPIError("get_def() is not implemented")

    def get_match(self, pattern: str) -> List[Any]:
        """
        Get registers matching a specific pattern.

        This is an abstract method that should be implemented by subclasses
        that support pattern matching.

        Args:
            pattern: Pattern to match against register names

        Returns:
            List of matching register definitions

        Raises:
            UnimplementedAPIError: If the subclass does not implement this method
        """
        raise UnimplementedAPIError("get_match() is not implemented")
