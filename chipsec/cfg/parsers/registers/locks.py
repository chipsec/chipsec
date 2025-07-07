# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2023, Intel Corporation
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

"""
Lock Register Helper configuration parser and accessor.

This module provides LOCKSHelper class for parsing and managing lock register configurations
in the CHIPSEC framework. Lock helpers provide access to lock bits and dependency management.
"""

from typing import Optional
from collections import namedtuple
from chipsec.library.exceptions import CSConfigError


class LockHelperError(CSConfigError):
    """Exception raised for lock helper-specific errors."""
    pass


class LOCKSHelper(namedtuple('LocksHelper', 'register field attributes lock_value dependency dependency_value')):
    """
    Lock Register Helper configuration parser and accessor.

    This class handles parsing and access to lock register configurations, providing
    functionality for lock bit management and dependency tracking.

    Attributes:
        register (str): Name of the register containing the lock
        field (str): Name of the field within the register
        attributes (str): Access attributes for the lock
        lock_value (Optional[int]): Value that indicates locked state
        dependency (Optional[str]): Name of dependency register/field
        dependency_value (Optional[int]): Value of dependency that enables this lock

    Example:
        >>> lock = LOCKSHelper(
        ...     register='CONTROL_REG',
        ...     field='LOCK_BIT',
        ...     attributes='RW1S',
        ...     lock_value=1,
        ...     dependency=None,
        ...     dependency_value=None
        ... )
        >>> print(lock.has_lock_value())
        True
    """

    __slots__ = ()

    def has_lock_value(self) -> bool:
        """
        Check if this lock has a defined lock value.

        Returns:
            True if lock_value is defined, False otherwise
        """
        return self.lock_value is not None

    def is_access_type(self, attributes: str) -> bool:
        """
        Check if this lock matches the specified access attributes.

        Args:
            attributes: Access attributes to check against

        Returns:
            True if attributes match, False otherwise
        """
        return self.attributes == attributes

    def has_dependency(self) -> bool:
        """
        Check if this lock has a dependency.

        Returns:
            True if dependency is defined, False otherwise
        """
        return self.dependency is not None

    def has_dependency_value(self) -> bool:
        """
        Check if this lock has a dependency value defined.

        Returns:
            True if dependency_value is defined, False otherwise
        """
        return self.dependency_value is not None

    def is_read_only(self) -> bool:
        """
        Check if this lock is read-only.

        Returns:
            True if attributes indicate read-only access
        """
        return self.attributes in ['RO', 'ROS']

    def is_write_once(self) -> bool:
        """
        Check if this lock is write-once (write 1 to set).

        Returns:
            True if attributes indicate write-once behavior
        """
        return self.attributes in ['RW1S', 'WO1S']

    def is_clearable(self) -> bool:
        """
        Check if this lock can be cleared.

        Returns:
            True if attributes allow clearing the lock
        """
        return self.attributes in ['RW', 'RW1C', 'WO1C']

    def get_lock_info(self) -> dict:
        """
        Get comprehensive lock information.

        Returns:
            Dictionary containing lock configuration details
        """
        return {
            'register': self.register,
            'field': self.field,
            'attributes': self.attributes,
            'lock_value': self.lock_value,
            'dependency': self.dependency,
            'dependency_value': self.dependency_value,
            'has_lock_value': self.has_lock_value(),
            'has_dependency': self.has_dependency(),
            'is_read_only': self.is_read_only(),
            'is_write_once': self.is_write_once(),
            'is_clearable': self.is_clearable()
        }

    def __str__(self) -> str:
        """
        String representation of lock helper.

        Returns:
            Formatted string with lock details
        """
        parts = [f"Lock: {self.register}.{self.field}"]
        parts.append(f"Attributes: {self.attributes}")

        if self.has_lock_value():
            parts.append(f"Lock Value: 0x{self.lock_value:X}")

        if self.has_dependency():
            dep_str = f"Dependency: {self.dependency}"
            if self.has_dependency_value():
                dep_str += f" = 0x{self.dependency_value:X}"
            parts.append(dep_str)

        return f"LOCKSHelper({', '.join(parts)})"

    def __repr__(self) -> str:
        """
        Detailed string representation for debugging.

        Returns:
            Detailed string representation
        """
        return (f"LOCKSHelper(register='{self.register}', field='{self.field}', "
                f"attributes='{self.attributes}', lock_value={self.lock_value}, "
                f"dependency={self.dependency}, dependency_value={self.dependency_value})")


def create_lock_helper(register: str, field: str, attributes: str,
                      lock_value: Optional[int] = None,
                      dependency: Optional[str] = None,
                      dependency_value: Optional[int] = None) -> LOCKSHelper:
    """
    Create a LOCKSHelper instance with validation.

    Args:
        register: Name of the register containing the lock
        field: Name of the field within the register
        attributes: Access attributes for the lock
        lock_value: Value that indicates locked state
        dependency: Name of dependency register/field
        dependency_value: Value of dependency that enables this lock

    Returns:
        LOCKSHelper instance

    Raises:
        LockHelperError: If configuration is invalid
    """
    if not register:
        raise LockHelperError("Register name cannot be empty")

    if not field:
        raise LockHelperError("Field name cannot be empty")

    if not attributes:
        raise LockHelperError("Attributes cannot be empty")

    valid_attributes = ['RO', 'RW', 'ROS', 'RW1S', 'RW1C', 'WO1S', 'WO1C']
    if attributes not in valid_attributes:
        raise LockHelperError(f"Invalid attributes '{attributes}'. Must be one of: {', '.join(valid_attributes)}")

    return LOCKSHelper(
        register=register,
        field=field,
        attributes=attributes,
        lock_value=lock_value,
        dependency=dependency,
        dependency_value=dependency_value
    )
