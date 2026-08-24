# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2026, Intel Corporation
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
HOB (Hand-Off Block) configuration parser.

This module provides the HOBConfig class describing a <definition> entry of the
top-level <hob> section. The definition names the IP node that holds the HOB
structure declarations pulled in from its config file(s).
"""

from typing import Dict, Any

from chipsec.cfg.parsers.ip.generic import GenericConfig
from chipsec.library.exceptions import GenericConfigError


class HOBConfig(GenericConfig):
    """
    HOB definition group configuration.

    Example:
        >>> hob_cfg = HOBConfig({'name': 'HOB', 'config': ['HOB.hob0.xml']})
        >>> print(hob_cfg.name)
        HOB
    """

    def __init__(self, cfg_obj: Dict[str, Any]) -> None:
        """
        Initialize HOB configuration.

        Args:
            cfg_obj: Dictionary containing HOB definition data

        Raises:
            GenericConfigError: If configuration validation fails
        """
        super().__init__(cfg_obj)
        if not self.config:
            raise GenericConfigError(f'HOB definition {self.name} has no config file')
