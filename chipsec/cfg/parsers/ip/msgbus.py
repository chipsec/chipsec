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
MSGBUS (Message Bus) configuration parser.

This module provides MSGBUSConfig class for parsing and managing message bus configurations in the CHIPSEC framework.
Message buses provide communication interfaces between different platform components.
"""

from typing import Dict, Any, Optional
from chipsec.cfg.parsers.ip.generic import GenericConfig
from chipsec.library.exceptions import MSGBUSConfigError

class MSGBUSConfig(GenericConfig):
    """
    MSGBUS (Message Bus) configuration parser.

    This class handles parsing and validation of message bus configurations, extending
    the base GenericConfig with MSGBUS-specific functionality including port management.

    Attributes:
        name (str): The name of the MSGBUS configuration
        config (Dict[str, Any]): The raw configuration data
        port (Union[int, str]): The message bus port identifier

    Example:
        >>> msgbus_cfg = MSGBUSConfig({'name': 'PUNIT_MSGBUS', 'port': 0x04})
        >>> print(msgbus_cfg.port)
        4
    """

    def __init__(self, cfg_obj: Dict[str, Any]) -> None:
        """
        Initialize MSGBUS configuration.

        Args:
            cfg_obj: Dictionary containing MSGBUS configuration data

        Raises:
            MSGBUSConfigError: If configuration validation fails
        """
        try:
            super().__init__(cfg_obj)
            self.port = cfg_obj['port']
            self._validate_msgbus_config()
        except KeyError as e:
            raise MSGBUSConfigError(f"Missing required field in MSGBUS configuration: {e}") from e
        except Exception as e:
            raise MSGBUSConfigError(f"Failed to initialize MSGBUS configuration: {e}") from e

    def _validate_msgbus_config(self) -> None:
        """
        Validate MSGBUS-specific configuration requirements.

        Raises:
            MSGBUSConfigError: If configuration is invalid
        """
        if not self.name:
            raise MSGBUSConfigError("MSGBUS configuration must have a valid name")

        if self.port is None:
            raise MSGBUSConfigError("MSGBUS configuration must have a valid port")

        # Validate port format and range
        port_int = self.get_port_as_int()
        if port_int is None or port_int < 0 or port_int > 0xFF:
            raise MSGBUSConfigError(f"Invalid port value: {self.port}. Must be 0-255 range")

    def get_port_as_int(self) -> Optional[int]:
        """
        Get the port as an integer value.

        Returns:
            Port as integer, or None if conversion fails
        """
        try:
            if isinstance(self.port, str):
                return int(self.port, 0)
            return int(self.port)
        except (ValueError, TypeError):
            return None

    def get_port_as_hex(self) -> str:
        """
        Get the port as a hexadecimal string.

        Returns:
            Port as hex string (e.g., '0x04')
        """
        port_int = self.get_port_as_int()
        return f"0x{port_int:02X}" if port_int is not None else "0x00"

    def is_valid_port(self) -> bool:
        """
        Check if the port value is valid.

        Returns:
            True if port is valid, False otherwise
        """
        port_int = self.get_port_as_int()
        return port_int is not None and 0 <= port_int <= 0xFF

    def __str__(self) -> str:
        """
        String representation of MSGBUS configuration.

        Returns:
            Formatted string with MSGBUS details
        """
        port_hex = self.get_port_as_hex()
        return f"MSGBUSConfig(name='{self.name}', port={port_hex}, config={self.config})"

    def __repr__(self) -> str:
        """
        Detailed string representation for debugging.

        Returns:
            Detailed string representation
        """
        return f"MSGBUSConfig(name='{self.name}', port={self.port}, config={self.config})"
