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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.
#
# Contact information:
# chipsec@intel.com

"""
Lock helper classes for CHIPSEC configuration parsing.

This module provides helper classes for managing lock configurations,
including validation and access control for hardware register locks.
"""

from collections import namedtuple
from typing import Optional, Dict, Any


class LOCKSHelper(namedtuple('LocksHelper', 'register field attributes lock_value dependency dependency_value')):
    """
    Helper class for managing hardware register lock configurations.

    This class represents a lock configuration that controls access to
    specific register fields. Locks can have dependencies and specific
    values that must be set to enable or disable the lock.

    Attributes:
        register: Register name containing the lock
        field: Field name within the register (optional)
        attributes: Lock access attributes
        lock_value: Value that activates the lock (optional)
        dependency: Dependency register for the lock (optional)
        dependency_value: Required dependency value (optional)
    """
    __slots__ = ()

    def has_lock_value(self) -> bool:
        """
        Check if this lock has a specific activation value.

        Returns:
            True if lock_value is specified, False otherwise
        """
        return self.lock_value is not None

    def is_access_type(self, attributes: str) -> bool:
        """
        Check if the lock matches the specified access attributes.

        Args:
            attributes: Access attributes to check against

        Returns:
            True if attributes match, False otherwise
        """
        return self.attributes == attributes

    def has_dependency(self) -> bool:
        """
        Check if this lock has a dependency on another register.

        Returns:
            True if dependency is specified, False otherwise
        """
        return self.dependency is not None

    def get_field(self) -> str:
        """
        Get the field name for this lock.

        Returns:
            Field name or "N/A" if not specified
        """
        return self.field if self.field else "N/A"

    def get_register(self) -> str:
        """
        Get the register name for this lock.

        Returns:
            Register name or "N/A" if not specified
        """
        return self.register if self.register else "N/A"

    def get_dependency_info(self) -> str:
        """
        Get dependency information as a formatted string.

        Returns:
            Dependency info string or "None" if no dependency
        """
        if not self.has_dependency():
            return "None"

        dep_value = (f" = {self.dependency_value}"
                     if self.dependency_value is not None else "")
        return f"{self.dependency}{dep_value}"

    def is_active_with_value(self, value: Optional[int]) -> bool:
        """
        Check if the lock would be active with the given value.

        Args:
            value: Value to check against lock_value

        Returns:
            True if lock would be active, False otherwise
        """
        if not self.has_lock_value():
            # If no specific lock value, any non-None value activates
            return value is not None

        return value == self.lock_value

    def validate_configuration(self) -> bool:
        """
        Validate that the lock configuration is valid.

        Returns:
            True if configuration is valid, False otherwise
        """
        # Must have at least a register
        if not self.register:
            return False

        # If dependency is specified, it should be a valid string
        if self.dependency is not None and not isinstance(self.dependency, str):
            return False

        return True

    def matches_register_field(self, register: str, field: Optional[str] = None) -> bool:
        """
        Check if this lock matches the specified register and field.

        Args:
            register: Register name to match
            field: Optional field name to match

        Returns:
            True if register (and field) match, False otherwise
        """
        if self.register != register:
            return False

        if field is not None:
            return self.field == field

        return True

    def get_full_name(self) -> str:
        """
        Get the full name of the lock including register and field.

        Returns:
            Full lock name as "register.field" or just "register" if no field
        """
        if self.field:
            return f"{self.register}.{self.field}"
        return self.register

    def is_compatible_with(self, other: 'LOCKSHelper') -> bool:
        """
        Check if this lock is compatible with another lock.

        Args:
            other: Another LOCKSHelper instance

        Returns:
            True if locks are compatible (can coexist), False otherwise
        """
        if not isinstance(other, LOCKSHelper):
            return False

        # Same register+field is incompatible
        if self.register == other.register and self.field == other.field:
            return False

        # Check for dependency conflicts
        if (self.dependency == other.register or
                other.dependency == self.register):
            return False

        return True

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert lock to dictionary representation.

        Returns:
            Dictionary representation of the lock
        """
        return {
            'register': self.register,
            'field': self.field,
            'attributes': self.attributes,
            'lock_value': self.lock_value,
            'dependency': self.dependency,
            'dependency_value': self.dependency_value,
            'full_name': self.get_full_name(),
            'has_dependency': self.has_dependency(),
            'has_lock_value': self.has_lock_value()
        }

    def __str__(self) -> str:
        """Return detailed string representation of the lock."""
        parts = [f"Register: {self.get_register()}"]

        if self.field:
            parts.append(f"Field: {self.field}")

        if self.attributes:
            parts.append(f"Access: {self.attributes}")

        if self.has_lock_value():
            parts.append(f"Lock Value: {self.lock_value}")

        if self.has_dependency():
            parts.append(f"Dependency: {self.get_dependency_info()}")

        return "Lock(" + ", ".join(parts) + ")"

    def __repr__(self) -> str:
        """Return concise representation suitable for debugging."""
        return (f'LOCKSHelper(register="{self.register}", '
                f'field="{self.field}", '
                f'attributes="{self.attributes}", '
                f'lock_value={self.lock_value}, '
                f'dependency="{self.dependency}", '
                f'dependency_value={self.dependency_value})')


# Convenience functions for creating locks
def create_simple_lock(register: str, field: Optional[str] = None) -> LOCKSHelper:
    """
    Create a simple lock without dependencies or specific values.

    Args:
        register: Register name
        field: Optional field name

    Returns:
        New LOCKSHelper instance
    """
    return LOCKSHelper(register, field, None, None, None, None)


def create_value_lock(register: str, field: Optional[str], lock_value: int,
                     attributes: Optional[str] = None) -> LOCKSHelper:
    """
    Create a lock with a specific activation value.

    Args:
        register: Register name
        field: Optional field name
        lock_value: Value that activates the lock
        attributes: Optional access attributes

    Returns:
        New LOCKSHelper instance
    """
    return LOCKSHelper(register, field, attributes, lock_value, None, None)


def create_dependent_lock(register: str, field: Optional[str],
                         dependency: str, dependency_value: Optional[int] = None,
                         attributes: Optional[str] = None) -> LOCKSHelper:
    """
    Create a lock with a dependency on another register.

    Args:
        register: Register name
        field: Optional field name
        dependency: Dependency register name
        dependency_value: Optional required dependency value
        attributes: Optional access attributes

    Returns:
        New LOCKSHelper instance
    """
    return LOCKSHelper(register, field, attributes, None, dependency, dependency_value)
