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
MM_MSGBUS (Memory-Mapped Message Bus) configuration parser.

This module provides MM_MSGBUSConfig class for parsing and managing memory-mapped message bus configurations
in the CHIPSEC framework. Memory-mapped message buses provide MMIO-based communication interfaces.
"""

from typing import Dict, Any, Optional
from chipsec.cfg.parsers.ip.generic import GenericConfig
from chipsec.library.exceptions import MM_MSGBUSConfigError

class MM_MSGBUSConfig(GenericConfig):
    """
    MM_MSGBUS (Memory-Mapped Message Bus) configuration parser.

    This class handles parsing and validation of memory-mapped message bus configurations,
    extending the base GenericConfig with MM_MSGBUS-specific functionality including port management.

    Attributes:
        name (str): The name of the MM_MSGBUS configuration
        config (Dict[str, Any]): The raw configuration data
        port (Union[int, str]): The memory-mapped message bus port identifier

    Example:
        >>> mm_msgbus_cfg = MM_MSGBUSConfig({'name': 'PUNIT_MM_MSGBUS', 'port': 0x04})
        >>> print(mm_msgbus_cfg.port)
        4
    """

    def __init__(self, cfg_obj: Dict[str, Any]) -> None:
        """
        Initialize MM_MSGBUS configuration.

        Args:
            cfg_obj: Dictionary containing MM_MSGBUS configuration data

        Raises:
            MM_MSGBUSConfigError: If configuration validation fails
        """
        try:
            super().__init__(cfg_obj)
            self.port = cfg_obj['port']
            self._validate_mm_msgbus_config()
        except KeyError as e:
            raise MM_MSGBUSConfigError(f"Missing required field in MM_MSGBUS configuration: {e}") from e
        except Exception as e:
            raise MM_MSGBUSConfigError(f"Failed to initialize MM_MSGBUS configuration: {e}") from e

    def _validate_mm_msgbus_config(self) -> None:
        """
        Validate MM_MSGBUS-specific configuration requirements.

        Raises:
            MM_MSGBUSConfigError: If configuration is invalid
        """
        if not self.name:
            raise MM_MSGBUSConfigError("MM_MSGBUS configuration must have a valid name")

        if self.port is None:
            raise MM_MSGBUSConfigError(f"MM_MSGBUS configuration for {self.name} must have a valid port")

        # Validate port format and range
        port_int = self.get_port_as_int()
        if port_int is None or port_int < 0 or port_int > 0xFF:
            raise MM_MSGBUSConfigError(f"MM_MSGBUS configuration for {self.name} has invalid port value: {self.port}. Must be 0-255 range")

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

    def is_memory_mapped(self) -> bool:
        """
        Check if this is a memory-mapped message bus configuration.

        Returns:
            True (always, as this is an MM_MSGBUS)
        """
        return True

    def __str__(self) -> str:
        """
        String representation of MM_MSGBUS configuration.

        Returns:
            Formatted string with MM_MSGBUS details
        """
        port_hex = self.get_port_as_hex()
        return f"MM_MSGBUSConfig(name='{self.name}', port={port_hex}, config={self.config})"

    def __repr__(self) -> str:
        """
        Detailed string representation for debugging.

        Returns:
            Detailed string representation
        """
        return f"MM_MSGBUSConfig(name='{self.name}', port={self.port}, config={self.config})"
