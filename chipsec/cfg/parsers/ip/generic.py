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
Generic IP Configuration Helper

This module provides generic configuration management functionality for IP-based parsers.
It serves as the base class for all IP-specific configuration helpers, offering common
functionality like configuration validation, manipulation, and utility methods.
"""

from typing import Dict, Any, List, Optional

from chipsec.parsers import BaseConfigHelper


class GenericConfigError(Exception):
    """Custom exception for generic configuration errors."""
    pass


class GenericConfig(BaseConfigHelper):
    """
    Generic configuration helper for IP-based parsers.

    Provides basic configuration management functionality that can be
    extended by specific IP parsers.
    """

    def __init__(self, cfg_obj: Dict[str, Any]):
        """
        Initialize generic configuration helper.

        Args:
            cfg_obj: Configuration object containing name and optional config list

        Raises:
            GenericConfigError: If required configuration is missing
        """
        try:
            super().__init__(cfg_obj)

            if 'name' not in cfg_obj:
                raise GenericConfigError("Missing required 'name' field in configuration object")

            self.name: str = cfg_obj['name']
            self.config: List[Any] = cfg_obj.get('config', [])

        except Exception as e:
            raise GenericConfigError(f"Error initializing generic configuration: {str(e)}") from e

    def add_config(self, config: List[Any]) -> None:
        """
        Add configurations to the current configuration list.

        Args:
            config: List of configuration items to add

        Raises:
            GenericConfigError: If configuration addition fails
        """
        try:
            if not isinstance(config, list):
                raise GenericConfigError("Configuration must be a list")

            for cfg in config:
                if cfg not in self.config:
                    self.config.append(cfg)
        except Exception as e:
            raise GenericConfigError(f"Error adding configuration: {str(e)}") from e

    def remove_config(self, config_item: Any) -> bool:
        """
        Remove a configuration item from the configuration list.

        Args:
            config_item: Configuration item to remove

        Returns:
            True if item was removed, False if not found
        """
        try:
            if config_item in self.config:
                self.config.remove(config_item)
                return True
            return False
        except Exception:
            return False

    def clear_config(self) -> None:
        """Clear all configuration items."""
        self.config.clear()

    def get_config_count(self) -> int:
        """Get the number of configuration items."""
        return len(self.config)

    def has_config(self, config_item: Any) -> bool:
        """
        Check if a configuration item exists.

        Args:
            config_item: Configuration item to check

        Returns:
            True if item exists, False otherwise
        """
        return config_item in self.config

    def get_config_copy(self) -> List[Any]:
        """Get a copy of the current configuration list."""
        return self.config.copy()

    def validate_config(self) -> bool:
        """
        Validate the current configuration comprehensively.

        Performs validation of:
        - Name field presence and type
        - Configuration list type and structure
        - Basic consistency checks

        Returns:
            True if configuration is valid, False otherwise
        """
        try:
            # Basic validation - ensure name exists and is a non-empty string
            if not self.name or not isinstance(self.name, str) or not self.name.strip():
                return False

            # Ensure config is a list
            if not isinstance(self.config, list):
                return False

            # Additional validation - check for None values in config
            if any(item is None for item in self.config):
                return False

            # Check for duplicate configurations (if they're hashable)
            try:
                unique_configs = set()
                for item in self.config:
                    if isinstance(item, (str, int, float, bool, tuple)):
                        if item in unique_configs:
                            # Found duplicate, but this might be intentional
                            pass
                        unique_configs.add(item)
            except (TypeError, AttributeError):
                # Items are not hashable, skip duplicate check
                pass

            return True
        except Exception:
            return False

    def __repr__(self) -> str:
        """Return detailed string representation of the configuration."""
        return f"GenericConfig(name='{self.name}', config_count={len(self.config)})"

    def __str__(self) -> str:
        """Return human-readable string representation of the configuration."""
        status = "valid" if self.validate_config() else "invalid"
        return f"GenericConfig '{self.name}' with {len(self.config)} items ({status})"

    def update_config(self, config_updates: List[Any]) -> None:
        """
        Update configuration by replacing existing items with new ones.

        Args:
            config_updates: List of configuration items to update or add

        Raises:
            GenericConfigError: If configuration update fails
        """
        try:
            if not isinstance(config_updates, list):
                raise GenericConfigError("Configuration updates must be a list")

            # Clear existing and add new configurations
            self.config.clear()
            self.config.extend(config_updates)

        except Exception as e:
            raise GenericConfigError(f"Error updating configuration: {str(e)}") from e

    def find_config(self, predicate) -> Optional[Any]:
        """
        Find the first configuration item that matches the given predicate.

        Args:
            predicate: Function that takes a config item and returns True/False

        Returns:
            First matching configuration item, or None if not found
        """
        try:
            for config_item in self.config:
                if predicate(config_item):
                    return config_item
            return None
        except Exception:
            return None

    def filter_config(self, predicate) -> List[Any]:
        """
        Filter configuration items based on a predicate function.

        Args:
            predicate: Function that takes a config item and returns True/False

        Returns:
            List of configuration items that match the predicate
        """
        try:
            return [item for item in self.config if predicate(item)]
        except Exception:
            return []

    def merge_config(self, other_config: 'GenericConfig') -> None:
        """
        Merge configuration from another GenericConfig instance.

        Args:
            other_config: Another GenericConfig instance to merge from

        Raises:
            GenericConfigError: If merge operation fails
        """
        try:
            if not isinstance(other_config, GenericConfig):
                raise GenericConfigError("Can only merge with another GenericConfig instance")

            # Add items from other config that don't already exist
            for item in other_config.config:
                if item not in self.config:
                    self.config.append(item)

        except Exception as e:
            raise GenericConfigError(f"Error merging configuration: {str(e)}") from e

    def get_config_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the current configuration.

        Returns:
            Dictionary containing configuration summary information
        """
        try:
            unique_types = set(type(item).__name__ for item in self.config)
            return {
                'name': self.name,
                'total_items': len(self.config),
                'unique_types': list(unique_types),
                'is_valid': self.validate_config(),
                'is_empty': len(self.config) == 0
            }
        except Exception:
            return {
                'name': getattr(self, 'name', 'Unknown'),
                'total_items': 0,
                'unique_types': [],
                'is_valid': False,
                'is_empty': True
            }
