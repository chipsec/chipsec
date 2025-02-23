# -*- coding: utf-8 -*-
# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2021, SentinelOne
# Copyright (c) 2021, Intel
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

"""
SMM_CODE_CHK_EN (SMM Call-Out) Protection check

SMM_CODE_CHK_EN is a bit found in the SMM_FEATURE_CONTROL register.
Once set to '1', any CPU that attempts to execute SMM code not within the ranges defined by the SMRR will assert an unrecoverable MCE.
As such, enabling and locking this bit is an important step in mitigating SMM call-out vulnerabilities.
This CHIPSEC module simply reads the register and checks that SMM_CODE_CHK_EN is set and locked.

Reference:
    - Intel 64 and IA-32 Architectures Software Developer Manual (SDM)
        - https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html

Usage:
    ``chipsec_main -m common.smm_code_chk``

Examples:
    >>> chipsec_main.py -m common.smm_code_chk

Registers used:
    - SMM_FEATURE_CONTROL.LOCK
    - SMM_FEATURE_CONTROL.SMM_CODE_CHK_EN

.. note::
    - SMM_FEATURE_CONTROL may not be defined or readable on all platforms.

"""
from chipsec.library.exceptions import HWAccessViolationError
from chipsec.module_common import BaseModule, BIOS, SMM
from chipsec.library.returncode import ModuleResult
from typing import List

TAGS = [BIOS, SMM]
METADATA_TAGS = ['OPENSOURCE', 'IA', 'COMMON', 'SMM_CODE_CHK']


class smm_code_chk(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.cs.set_scope({
            "SMM_FEATURE_CONTROL": "8086.MSR",
        })

    def is_supported(self) -> bool:
        if not self.cs.register.is_defined('SMM_FEATURE_CONTROL'):
            # The SMM_FEATURE_CONTROL register is available starting from:
            # * 4th Generation Intel® Core™ Processors (Haswell microarchitecture)
            # * Atom Processors Based on the Goldmont Microarchitecture
            self.logger.log_important('Register SMM_FEATURE_CONTROL not defined for platform.  Skipping module.')
            return False

        # The Intel SDM states that SMM_FEATURE_CONTROL can only be accessed while the CPU executes in SMM.
        # However, in reality many users report that there is no problem reading this register from outside of SMM.
        # Just to be on the safe side of things, we'll verify we can read this register successfully before moving on.
        self.smm_fc_reg = self.cs.register.get_list_by_name('SMM_FEATURE_CONTROL')
        try:
            self.smm_fc_reg.read()
        except HWAccessViolationError:
            self.logger.log_important('SMM_FEATURE_CONTROL is unreadable.  Skipping module.')
            return False
        else:
            return True

    def _check_SMM_Code_Chk_En(self) -> int:
        self.smm_fc_reg.print()
        enabled = self.smm_fc_reg.is_all_field_value(1, 'SMM_CODE_CHK_EN')
        locked = self.smm_fc_reg.is_all_field_value(1, 'LOCK')
        
        if enabled:
            if locked:
                res = ModuleResult.PASSED
            else:
                res = ModuleResult.FAILED
                self.result.setStatusBit(self.result.status.LOCKS)
        else:
            # MSR_SMM_MCA_CAP (the register that reports enhanced SMM capabilities) can only be read from SMM.
            # Thus, there is no way to tell whether the the CPU doesn't support SMM_CODE_CHK_EN in the first place,
            # or the CPU supports SMM_CODE_CHK_EN but the BIOS forgot to enable it.
            #
            # In either case, there is nothing that prevents SMM code from executing instructions outside the ranges defined by the SMRRs,
            # so we should at least issue a warning regarding that.
            res = ModuleResult.WARNING

        return res

    def check_SMM_Code_Chk_En(self) -> int:
        
        res = self._check_SMM_Code_Chk_En()

        if res == ModuleResult.FAILED:
            self.logger.log_failed('SMM_Code_Chk_En is enabled but not locked down')
            self.result.setStatusBit(self.result.status.LOCKS)
        elif res == ModuleResult.WARNING:
            self.logger.log_warning("""[*] SMM_Code_Chk_En is not enabled.
This can happen either because this feature is not supported by the CPU or because the BIOS forgot to enable it.
Please consult the Intel SDM to determine whether or not your CPU supports SMM_Code_Chk_En.""")
            self.result.setStatusBit(self.result.status.VERIFY)
        else:
            self.logger.log_passed('SMM_Code_Chk_En is enabled and locked down')

        return self.result.getReturnCode(res)

    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test('SMM_Code_Chk_En (SMM Call-Out) Protection')
        self.res = self.check_SMM_Code_Chk_En()
        return self.res
