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
Control helper classes for CHIPSEC configuration parsing.

This module provides helper classes for managing control configurations,
including reading and writing control values with proper error handling.
"""

from typing import Dict, Any, Optional, TYPE_CHECKING
from chipsec.parsers import BaseConfigHelper
from chipsec.library.logger import logger

if TYPE_CHECKING:
    # RegisterHelper type hint - actual import will be at runtime
    pass


class ControlError(Exception):
    """Exception raised when control operations fail."""
    pass


class CONTROLHelper(BaseConfigHelper):
    """
    Helper class for managing control configurations.

    Controls represent specific bit fields within registers that can be
    read and written to configure hardware behavior.
    """

    def __init__(self, cfg_obj: Dict[str, Any], reg_obj: Any):
        """
        Initialize control helper.

        Args:
            cfg_obj: Control configuration dictionary
            reg_obj: Register object containing the control field

        Raises:
            ControlError: If required configuration is missing
        """
        super(CONTROLHelper, self).__init__(cfg_obj)

        # Validate required configuration
        if not isinstance(cfg_obj, dict):
            raise ControlError("Control configuration must be a dictionary")

        required_fields = ['name', 'field']
        for field in required_fields:
            if field not in cfg_obj:
                msg = f"Missing required field '{field}' in control config"
                raise ControlError(msg)

        self.name = cfg_obj['name']
        self.value: Optional[int] = None
        self.desc = cfg_obj.get('desc', f"Control {self.name}")
        self.__reg = reg_obj
        self.instance = getattr(reg_obj, 'instance', None)
        self.field = cfg_obj['field']
        self.logger = logger()

    def read(self) -> int:
        """
        Read the control value from the register field.

        Returns:
            Current value of the control field

        Raises:
            ControlError: If read operation fails
        """
        try:
            if not hasattr(self.__reg, 'read_field'):
                msg = f"Register {self.__reg} does not support field reading"
                raise ControlError(msg)

            self.value = self.__reg.read_field(self.field)
            self.logger.log_debug(f"Read control {self.name}: {self.value}")
            return self.value

        except Exception as e:
            error_msg = f"Failed to read control {self.name}: {e}"
            self.logger.log_error(error_msg)
            raise ControlError(error_msg) from e

    def write(self, value: int) -> None:
        """
        Write a value to the control field.

        Args:
            value: Value to write to the control field

        Raises:
            ControlError: If write operation fails
        """
        try:
            if not isinstance(value, int):
                msg = f"Control value must be an integer, got {type(value)}"
                raise ValueError(msg)

            if not hasattr(self.__reg, 'write_field'):
                msg = f"Register {self.__reg} does not support field writing"
                raise ControlError(msg)

            self.__reg.write_field(self.field, value)
            self.value = value
            self.logger.log_debug(f"Wrote control {self.name}: {value}")

        except Exception as e:
            error_msg = f"Failed to write control {self.name} with value {value}: {e}"
            self.logger.log_error(error_msg)
            raise ControlError(error_msg) from e

    def get_register_name(self) -> str:
        """
        Get the name of the register containing this control.

        Returns:
            Register name
        """
        return getattr(self.__reg, 'name', 'Unknown Register')

    def get_current_value(self) -> Optional[int]:
        """
        Get the current cached value without reading from hardware.

        Returns:
            Current cached value or None if not read yet
        """
        return self.value

    def is_set(self) -> bool:
        """
        Check if the control is currently set (non-zero).

        Returns:
            True if control value is non-zero, False otherwise

        Raises:
            ControlError: If control value is not available
        """
        if self.value is None:
            raise ControlError(f"Control {self.name} value not read yet")
        return bool(self.value)

    def toggle(self) -> int:
        """
        Toggle the control value (0 -> 1, non-zero -> 0).

        Returns:
            New value after toggle

        Raises:
            ControlError: If toggle operation fails
        """
        try:
            current = self.read()
            new_value = 0 if current else 1
            self.write(new_value)
            return new_value
        except Exception as e:
            error_msg = f"Failed to toggle control {self.name}: {e}"
            self.logger.log_error(error_msg)
            raise ControlError(error_msg) from e

    def reset_to_default(self) -> None:
        """
        Reset the control to its default value if specified in configuration.

        Raises:
            ControlError: If no default value is specified or operation fails
        """
        if not hasattr(self, '_default_value'):
            raise ControlError(f"No default value specified for control {self.name}")

        try:
            self.write(self._default_value)
            self.logger.log_info(f"Reset control {self.name} to default value {self._default_value}")
        except Exception as e:
            error_msg = f"Failed to reset control {self.name} to default: {e}"
            self.logger.log_error(error_msg)
            raise ControlError(error_msg) from e

    def read_and_validate(self, expected_value: Optional[int] = None) -> int:
        """
        Read the control value and optionally validate against expected value.

        Args:
            expected_value: Optional expected value for validation

        Returns:
            Current control value

        Raises:
            ControlError: If read fails or validation fails
        """
        try:
            current_value = self.read()

            if expected_value is not None and current_value != expected_value:
                error_msg = (f"Control {self.name} validation failed: "
                             f"expected {expected_value}, got {current_value}")
                self.logger.log_warning(error_msg)
                raise ControlError(error_msg)

            return current_value
        except Exception as e:
            if isinstance(e, ControlError):
                raise
            error_msg = f"Failed to read and validate control {self.name}: {e}"
            self.logger.log_error(error_msg)
            raise ControlError(error_msg) from e

    def safe_write(self, value: int, verify: bool = True) -> bool:
        """
        Safely write a value with optional verification.

        Args:
            value: Value to write
            verify: Whether to read back and verify the written value

        Returns:
            True if write was successful (and verified if requested)

        Raises:
            ControlError: If write or verification fails
        """
        try:
            self.write(value)

            if verify:
                readback = self.read()
                if readback != value:
                    error_msg = (f"Control {self.name} write verification failed: "
                                 f"wrote {value}, read back {readback}")
                    self.logger.log_error(error_msg)
                    raise ControlError(error_msg)

            return True
        except Exception as e:
            if isinstance(e, ControlError):
                raise
            error_msg = f"Safe write failed for control {self.name}: {e}"
            self.logger.log_error(error_msg)
            raise ControlError(error_msg) from e

    def __str__(self) -> str:
        """Return string representation of control."""
        return f"""Control: {self.name}
        Description: {self.desc}
        Register: {self.get_register_name()}
        Field: {self.field}
        Value: {self.value}
        Instance: {self.instance}"""

    def __repr__(self) -> str:
        """Return detailed representation of control."""
        return (f'CONTROLHelper(name="{self.name}", '
                f'field="{self.field}", '
                f'value={self.value}, '
                f'register="{self.get_register_name()}")')

    def __eq__(self, other: Any) -> bool:
        """Compare controls for equality."""
        if not isinstance(other, CONTROLHelper):
            return False
        return (self.name == other.name and
                self.field == other.field and
                self.get_register_name() == other.get_register_name())

    def __hash__(self) -> int:
        """Return hash of control for use in sets/dicts."""
        return hash((self.name, self.field, self.get_register_name()))
