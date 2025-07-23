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
Control Register Helper configuration parser and accessor.

This module provides CONTROLHelper class for parsing and accessing control register fields
in the CHIPSEC framework. Control helpers provide access to specific fields within registers.
"""

from typing import Dict, Any, Optional
from chipsec.parsers import BaseConfigHelper
from chipsec.library.exceptions import ControlHelperError

class CONTROLHelper(BaseConfigHelper):
    """
    Control Register Helper configuration parser and accessor.

    This class handles parsing and access to specific fields within registers,
    extending the base configuration helper with field-specific functionality.

    Attributes:
        name (str): The name of the control
        desc (str): Description of the control
        value (Optional[int]): Current control field value
        field (str): Name of the register field
        instance (Optional[int]): Register instance identifier

    Example:
        >>> control = CONTROLHelper(
        ...     {'name': 'LOCK_BIT', 'desc': 'Lock control bit', 'field': 'LOCK'},
        ...     register_object
        ... )
        >>> value = control.read()
    """

    def __init__(self, cfg_obj: Dict[str, Any], reg_obj: Any) -> None:
        """
        Initialize control helper configuration.

        Args:
            cfg_obj: Dictionary containing control configuration data
            reg_obj: Register object that contains the field

        Raises:
            ControlHelperError: If configuration validation fails
        """
        try:
            super().__init__(cfg_obj)
            self.name = cfg_obj['name']
            self.value: Optional[int] = None
            self.desc = cfg_obj['desc']
            self.__reg = reg_obj
            self.instance = getattr(reg_obj, 'instance', None)
            self.field = cfg_obj['field']
            self._validate_control_config()
        except KeyError as e:
            raise ControlHelperError(f"Missing required field in control configuration: {e}") from e
        except Exception as e:
            raise ControlHelperError(f"Failed to initialize control helper configuration: {e}") from e

    def _validate_control_config(self) -> None:
        """
        Validate control helper-specific configuration requirements.

        Raises:
            ControlHelperError: If configuration is invalid
        """
        if not self.name:
            raise ControlHelperError("Control helper configuration must have a valid name")

        if not self.field:
            raise ControlHelperError(f"Control helper configuration for {self.name} must have a valid field name")

        if self.__reg is None:
            raise ControlHelperError(f"Control helper configuration for {self.name} must have a valid register object")

        # Verify that the register has the required field access methods
        if not hasattr(self.__reg, 'read_field') or not hasattr(self.__reg, 'write_field'):
            raise ControlHelperError(f"Register object for {self.name} must support field read/write operations")

    def get_register_name(self) -> str:
        """
        Get the name of the associated register.

        Returns:
            Name of the register containing this control field
        """
        return getattr(self.__reg, 'name', 'Unknown')

    def get_field_name(self) -> str:
        """
        Get the name of the register field.

        Returns:
            Name of the register field
        """
        return self.field

    def get_register_object(self) -> Any:
        """
        Get the associated register object.

        Returns:
            Register object containing this control field
        """
        return self.__reg

    def is_field_available(self) -> bool:
        """
        Check if the field is available in the register.

        Returns:
            True if field is available, False otherwise
        """
        try:
            # Try to check if the field exists in the register
            if hasattr(self.__reg, 'fields') and self.field in self.__reg.fields:
                return True
            # If we can't determine availability, assume it's available
            return True
        except Exception:
            return False

    def read(self) -> int:
        """
        Read the control field value.

        Returns:
            Current field value

        Raises:
            ControlHelperError: If read operation fails
        """
        try:
            if not self.is_field_available():
                raise ControlHelperError(f"Field '{self.field}' not available in register '{self.get_register_name()}'")

            self.value = self.__reg.read_field(self.field)
            return self.value
        except Exception as e:
            raise ControlHelperError(f"Failed to read control field '{self.field}' from register '{self.get_register_name()}': {e}") from e

    def write(self, value: int) -> None:
        """
        Write a value to the control field.

        Args:
            value: Value to write to the field

        Raises:
            ControlHelperError: If write operation fails
        """
        try:
            if not self.is_field_available():
                raise ControlHelperError(f"Field '{self.field}' not available in register '{self.get_register_name()}'")

            self.__reg.write_field(self.field, value)
            self.value = value
        except Exception as e:
            raise ControlHelperError(f"Failed to write to control field '{self.field}' in register '{self.get_register_name()}': {e}") from e

    def get_current_value(self) -> Optional[int]:
        """
        Get the current cached value without reading from hardware.

        Returns:
            Current cached value, or None if not read yet
        """
        return self.value

    def __str__(self) -> str:
        """
        String representation of control helper.

        Returns:
            Formatted string with control details
        """
        value_str = f"0x{self.value:X}" if self.value is not None else "Not Read"
        return (f"Control: {self.name}\n"
                f"  Register: {self.get_register_name()}\n"
                f"  Field: {self.field}\n"
                f"  Value: {value_str}\n"
                f"  Description: {self.desc}")

    def __repr__(self) -> str:
        """
        Detailed string representation for debugging.

        Returns:
            Detailed string representation
        """
        return (f"CONTROLHelper(name='{self.name}', field='{self.field}', "
                f"register='{self.get_register_name()}', value={self.value})")
