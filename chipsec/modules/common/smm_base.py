# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
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
Compatible SMM memory (SMRAM) Memory Protection check module

Reference:

usage:
    ``chipsec_main -m common.smm_base``

Examples:
    >>> chipsec_main.py -m common.smm_base

This module will only run on platforms that have SMM_BASE defined.
"""

from chipsec.module_common import BaseModule, MTAG_BIOS, MTAG_SMM
from chipsec.library.returncode import ModuleResult
from typing import List

TAGS = [MTAG_BIOS, MTAG_SMM]

class smm_base(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        #CAD TODO self.result.id = 0x3486891
        #CAD TODO self.result.url = 'https://chipsec.github.io/modules/chipsec.modules.common.smm.html'

    def is_supported(self) -> bool:
        if self.cs.is_amd():
            return self.cs.register.is_defined('SMMMask')
        self.logger.log("smm_base is an AMD only module. Skipping module.")
        return False

    def check_SMMBase(self) -> int:

        regval = self.cs.register.read('SMMADDR')
        self.cs.register.print('SMMADDR', regval)
        TsegBase = self.cs.register.get_field('SMMADDR', regval, 'TSEGBASE')

        regval = self.cs.register.read('SMMMASK')
        self.cs.register.print('SMMMASK', regval)
        TsegMask = self.cs.register.get_field('SMMMASK', regval, 'TSEGMASK')
        TsegValid = bool(self.cs.register.get_field('SMMMASK', regval, 'TVALID'))
        AsegValid = bool(self.cs.register.get_field('SMMMASK', regval, 'AVALID'))

        if(TsegValid and AsegValid):
            self.logger.log_passed("SMM Memory both Tseg and Aseg are Valid")
            res = ModuleResult.PASSED
        else:
            self.logger.log_failed(f"Tseg Valid {TsegValid}, Aseg Valid {AsegValid}")
            res = ModuleResult.FAILED

        return self.result.getReturnCode(res)

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test("Compatible SMM memory (SMRAM) Protection")
        return self.check_SMMBase()
