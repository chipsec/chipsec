# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2024, AMD Corporation
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
# chipsec@amd.com
#

"""
Compatible SMM memory (SMRAM) Protection check module
This CHIPSEC module simply reads HWCR and checks that D_LCK is set.

Reference:

usage:
    ``chipsec_main -m common.smm_lock``

Examples:
    >>> chipsec_main.py -m common.smm_lock

This module will only run on platforms that have HWCR defined.
"""

from chipsec.module_common import BaseModule, BIOS, SMM
from chipsec.library.returncode import ModuleResult
from typing import List

TAGS = [BIOS, SMM]
METADATA_TAGS = ['OPENSOURCE', 'IA', 'COMMON', 'SMM_LOCK']


class smm_lock(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self) -> bool:
        if self.cs.is_amd():
            return self.cs.register.is_defined('HWCR')
        self.logger.log("'HWCR' not defined for platform. Skipping module.")
        return False

    def check_HWCR(self) -> int:

        regval = self.cs.register.read('HWCR')
        SmmLock = self.cs.register.get_field('HWCR', regval, 'SmmLock')

        self.cs.register.print('HWCR', regval)

        if (1 == SmmLock):
            res = ModuleResult.PASSED
            self.logger.log_passed("Smm is Locked")
        else:
            res = ModuleResult.FAILED
            if (0 == SmmLock):
                self.logger.log_failed("Smm Code is Not Locked")
            self.result.setStatusBit(self.rc_res.status.LOCKS)

        return self.result.getReturnCode(res)

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test("Compatible SMM Memory (SMRAM) Lock Protection")
        return self.check_HWCR()
