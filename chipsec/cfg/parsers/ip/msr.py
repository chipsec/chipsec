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
MSR (Model Specific Register) configuration parser.

This module provides MSRConfig class for parsing and managing MSR configurations in the CHIPSEC framework.
MSRs are CPU-specific registers that provide access to processor features and debugging capabilities.
"""

from typing import Dict, Any, Optional
from chipsec.cfg.parsers.ip.generic import GenericConfig
from chipsec.library.exceptions import MSRConfigError


class MSRConfig(GenericConfig):
    """
    MSR (Model Specific Register) configuration parser.

    This class handles parsing and validation of MSR configurations, extending
    the base GenericConfig with MSR-specific functionality.

    Attributes:
        name (str): The name of the MSR configuration
        config (Dict[str, Any]): The raw configuration data

    Example:
        >>> msr_cfg = MSRConfig({'name': 'IA32_MTRR_CAP', 'address': 0xFE})
        >>> print(msr_cfg.name)
        IA32_MTRR_CAP
    """

    def __init__(self, cfg_obj: Dict[str, Any]) -> None:
        """
        Initialize MSR configuration.

        Args:
            cfg_obj: Dictionary containing MSR configuration data

        Raises:
            MSRConfigError: If configuration validation fails
        """
        try:
            self._cfg_obj = cfg_obj  # Store original config for reference
            super().__init__(cfg_obj)
            self._validate_msr_config()
        except Exception as e:
            raise MSRConfigError(f"Failed to initialize MSR configuration: {e}") from e

    def _validate_msr_config(self) -> None:
        """
        Validate MSR-specific configuration requirements.

        Raises:
            MSRConfigError: If configuration is invalid
        """
        if not self.name:
            raise MSRConfigError("MSR configuration must have a valid name")

        # MSRs typically should have an address or some identifier
        # Check both in config dict and as top-level attributes
        has_address = ('address' in self.config or 'msr' in self.config or
                      hasattr(self, 'address') or hasattr(self, 'msr'))
        if not has_address:
            # This is a warning rather than an error for backward compatibility
            pass

    def get_address(self) -> Optional[int]:
        """
        Get the MSR address.

        Returns:
            MSR address as integer, or None if not specified
        """
        # First check in the original cfg_obj if available
        if hasattr(self, '_cfg_obj'):
            address = self._cfg_obj.get('address') or self._cfg_obj.get('msr')
        else:
            # Fallback to checking if we have direct attributes
            address = getattr(self, 'address', None) or getattr(self, 'msr', None)

        if address is not None:
            try:
                return int(address, 0)
            except (ValueError, TypeError):
                return None
        return None

    def is_valid_address(self) -> bool:
        """
        Check if the MSR has a valid address.

        Returns:
            True if address is valid, False otherwise
        """
        address = self.get_address()
        return address is not None and 0 <= address <= 0xFFFFFFFF

    def __str__(self) -> str:
        """
        String representation of MSR configuration.

        Returns:
            Formatted string with MSR details
        """
        address = self.get_address()
        address_str = f"0x{address:X}" if address is not None else "N/A"
        return f"MSRConfig(name='{self.name}', address={address_str}, config={self.config})"

    def __repr__(self) -> str:
        """
        Detailed string representation for debugging.

        Returns:
            Detailed string representation
        """
        return f"MSRConfig(name='{self.name}', config={self.config})"
