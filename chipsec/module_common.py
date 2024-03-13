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

    def is_supported(self):
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
    def update_res(self, value):
        if value not in result_priority:
            self.logger.log_verbose(f'Attempting to set invalid result status: {value}')
            return
        cur_priority = result_priority[self.res]
        new_priority = result_priority[value]
        if new_priority >= cur_priority:
            self.res = value
    # -------------------------------------------------------

    def run(self, module_argv):
        raise NotImplementedError('Sub-class should overwrite the run() method')


MTAG_BIOS = 'BIOS'
MTAG_SMM = 'SMM'
MTAG_SECUREBOOT = 'SECUREBOOT'
MTAG_HWCONFIG = 'HWCONFIG'
MTAG_CPU = 'CPU'


# ! [Available Tags]
MTAG_METAS = {
    MTAG_BIOS: 'System Firmware (BIOS/UEFI) Modules',
    MTAG_SMM: 'System Management Mode (SMM) Modules',
    MTAG_SECUREBOOT: 'Secure Boot Modules',
    MTAG_HWCONFIG: 'Hardware Configuration Modules',
    MTAG_CPU: 'CPU Modules',
}
# ! [Available Tags]
MODULE_TAGS = dict([(_tag, []) for _tag in MTAG_METAS])

#
# Common module command line options
#
OPT_MODIFY = 'modify'
