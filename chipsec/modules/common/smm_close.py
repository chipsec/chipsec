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
This CHIPSEC module simply reads SMRAMC and checks that D_LCK is set.

Reference:
https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7014.html

usage:
    ``chipsec_main -m common.smm_close``

Examples:
    >>> chipsec_main.py -m common.smm_close

This module will only run on AMD platforms with SMMMask defined.
"""

from chipsec.module_common import BaseModule, BIOS, SMM
from chipsec.library.returncode import ModuleResult
from typing import List

TAGS = [BIOS, SMM]
METADATA_TAGS = ['OPENSOURCE', 'IA', 'COMMON', 'SMM_CLOSE']


class smm_close(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self) -> bool:
        if self.cs.is_amd():
            return self.cs.register.is_defined('SMMMASK')
        self.logger.log("smm_lose is an AMD only module. Skipping module.")
        return False

    def check_SMMClose(self) -> int:
        regval = self.cs.register.read('SMMMASK')
        self.cs.register.print('SMMMASK', regval)
        TSegClose = bool(self.cs.register.get_field('SMMMASK', regval, 'TCLOSE'))
        ASegClose = bool(self.cs.register.get_field('SMMMASK', regval, 'ACLOSE'))

        if (TSegClose or ASegClose):
            self.logger.log_failed(f"TSeg Close {TSegClose}, Aseg Valid {ASegClose}")
            res = ModuleResult.FAILED
        else:
            self.logger.log_passed("ASeg and TSeg are both closed")
            res = ModuleResult.PASSED

        return self.result.getReturnCode(res)

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test("Verifies AClose and TClose are clear.  Should be clear after SMI Handler.")
        self.res = self.check_SMMClose()

        return self.res
