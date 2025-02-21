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

"""

import chipsec.chipset
from chipsec.library.logger import logger
from chipsec.library.returncode import ModuleResult, ReturnCode, result_priority


class BaseModule:
    def __init__(self):
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
        This method should be overwritten by the module returning True or False
        depending whether or not this module is supported in the currently running
        platform.
        To access the currently running platform use
        """
        return True

    # -------------------------------------------------------
    # Legacy results
    # -------------------------------------------------------
    def update_res(self, value) -> None:
        if value not in result_priority:
            self.logger.log_verbose(f'Attempting to set invalid result status: {value}')
            return
        cur_priority = result_priority[self.res]
        new_priority = result_priority[value]
        if new_priority >= cur_priority:
            self.res = value
    # -------------------------------------------------------

    def run(self, module_argv) -> int:
        """
        This method should be overwritten by the module returning int
        """
        raise NotImplementedError('Sub-class should overwrite the run() method')


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
