# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2022, Intel Corporation
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
#


"""
Common include file for modules

This module provides the base class and common functionality for all CHIPSEC
security assessment modules.
"""

from typing import List
import chipsec.chipset
from chipsec.library.logger import logger
from chipsec.library.returncode import ModuleResult, ReturnCode, result_priority


class BaseModule:
    """
    Base class for all CHIPSEC security assessment modules.

    This class provides the common functionality and interface that all
    CHIPSEC modules should implement. It handles chipset access, logging,
    and result tracking.
    """

    def __init__(self) -> None:
        """
        Initialize the base module with chipset access and logging.
        """
        self.cs = chipsec.chipset.cs()
        self.logger = logger()
        self.result = ReturnCode(self.cs)
        # -------------------------------------------------------
        # Legacy results
        # -------------------------------------------------------
        self.res = ModuleResult.PASSED
        # -------------------------------------------------------

    def is_supported(self) -> bool:
        """
        Check if this module is supported on the current platform.

        This method should be overwritten by the module returning True or False
        depending whether or not this module is supported in the currently
        running platform.

        Returns:
            True if the module is supported, False otherwise
        """
        return True

    # -------------------------------------------------------
    # Legacy results
    # -------------------------------------------------------
    def update_res(self, value: ModuleResult) -> None:
        """
        Update the legacy result status.

        Args:
            value: The new result status to set
        """
        if value not in result_priority:
            msg = f'Attempting to set invalid result status: {value}'
            self.logger.log_verbose(msg)
            return
        cur_priority = result_priority[self.res]
        new_priority = result_priority[value]
        if new_priority >= cur_priority:
            self.res = value
    # -------------------------------------------------------

    def run(self, module_argv: List[str]) -> int:
        """
        Run the module with the given arguments.

        This method should be overwritten by the module returning an integer
        exit code.

        Args:
            module_argv: List of command line arguments for the module

        Returns:
            Integer exit code (0 for success, non-zero for failure)

        Raises:
            NotImplementedError: If the subclass doesn't implement this method
        """
        raise NotImplementedError(
            'Sub-class should overwrite the run() method')


BIOS = 'BIOS'
SMM = 'SMM'
SECUREBOOT = 'SECUREBOOT'
HWCONFIG = 'HWCONFIG'
CPU = 'CPU'
ARCHIVED = 'ARCHIVED'
IA = 'IA'
AMD = 'AMD'


# ! [Available Tags]
MODULE_TAG_METAS = {
    BIOS: 'System Firmware (BIOS/UEFI) Modules',
    SMM: 'System Management Mode (SMM) Modules',
    SECUREBOOT: 'Secure Boot Modules',
    HWCONFIG: 'Hardware Configuration Modules',
    CPU: 'CPU Modules',
    ARCHIVED: 'Archived Modules',
    IA: 'Intel Architecture Modules',
    AMD: 'AMD Modules'
}
# ! [Available Tags]
MODULE_TAGS = dict([(_tag, []) for _tag in MODULE_TAG_METAS])

OPT_MODIFY = 'modify'
