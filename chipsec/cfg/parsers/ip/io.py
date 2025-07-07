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
I/O Port IP Configuration Helper

Provides I/O port-specific configuration management functionality for
I/O port-based IP parsers.
"""

from typing import Dict, Any, Union

from chipsec.cfg.parsers.ip.generic import GenericConfig, GenericConfigError


class IOConfigError(GenericConfigError):
    """Custom exception for I/O configuration errors."""
    pass


class IOConfig(GenericConfig):
    """
    I/O configuration helper for I/O port-based IP regions.

    Handles configuration of I/O port-based IP including port addresses
    and access management.
    """

    def __init__(self, cfg_obj: Dict[str, Any]):
        """
        Initialize I/O configuration helper.

        Args:
            cfg_obj: Configuration object containing I/O-specific fields

        Raises:
            IOConfigError: If required I/O configuration is missing or invalid
        """
        try:
            super().__init__(cfg_obj)

            # Required field for I/O configuration
            if 'port' not in cfg_obj:
                raise IOConfigError("Missing required 'port' field")

            self.port: Union[int, str] = cfg_obj['port']

            # Validate configuration after initialization
            if not self.validate_io_config():
                raise IOConfigError("Invalid I/O configuration detected")

        except Exception as e:
            if isinstance(e, IOConfigError):
                raise
            raise IOConfigError(
                f"Error initializing I/O configuration: {str(e)}") from e

    def validate_io_config(self) -> bool:
        """
        Validate I/O-specific configuration.

        Returns:
            True if I/O configuration is valid, False otherwise
        """
        try:
            # Call parent validation first
            if not self.validate_config():
                return False

            # Validate port (can be int or hex string)
            if isinstance(self.port, str):
                try:
                    int(self.port, 16 if self.port.startswith('0x') else 10)
                except ValueError:
                    return False
            elif not isinstance(self.port, int):
                return False

            return True
        except Exception:
            return False

    def get_port_int(self) -> int:
        """
        Get port as integer value.

        Returns:
            Port as integer

        Raises:
            IOConfigError: If port cannot be converted to integer
        """
        try:
            if isinstance(self.port, int):
                return self.port
            elif isinstance(self.port, str):
                return int(self.port,
                           16 if self.port.startswith('0x') else 10)
            else:
                raise IOConfigError(f"Invalid port type: {type(self.port)}")
        except ValueError as e:
            raise IOConfigError(
                f"Cannot convert port to integer: {self.port}") from e

    def get_io_summary(self) -> Dict[str, Any]:
        """
        Get summary of I/O configuration.

        Returns:
            Dictionary with I/O configuration summary
        """
        try:
            return {
                'name': self.name,
                'port': self.get_port_int(),
                'is_valid': self.validate_io_config(),
                'config_items': len(self.config)
            }
        except Exception:
            return {
                'name': getattr(self, 'name', 'Unknown'),
                'port': 0,
                'is_valid': False,
                'config_items': 0
            }

    def __str__(self) -> str:
        """Return human-readable string representation."""
        try:
            port_str = f"0x{self.get_port_int():x}"
            ret = f'name: {self.name}, port: {port_str}'
            ret += f', config: {len(self.config)} items'
            return ret
        except Exception:
            # Fallback to basic representation if conversion fails
            ret = f'name: {self.name}, port: {self.port}'
            ret += f', config: {self.config}'
            return ret

    def __repr__(self) -> str:
        """Return detailed string representation."""
        return (f"IOConfig(name='{self.name}', port={self.port}, "
                f"config_count={len(self.config)})")
