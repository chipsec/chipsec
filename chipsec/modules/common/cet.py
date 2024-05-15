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
#

"""
Reports CET Settings

Usage:
  ``chipsec_main -m common.cet``

Example:
    >>> chipsec_main.py -m common.cet

.. note::
    - cpuid(7, 0) must return 1 at bit 7 to run
    - IA32_U_CET and IA32_S_CET must be defined for addition information.
    - Module is INFORMATION only and does NOT return a Pass/Fail
"""

from chipsec.module_common import BaseModule
from chipsec.library.returncode import ModuleResult
from chipsec.library.defines import BIT7, BIT20
from chipsec.library.exceptions import HWAccessViolationError


class cet(BaseModule):
    def __init__(self):
        super(cet, self).__init__()
        self.cpuid_7_0__ecx_val = None

    def is_supported(self):
        supported = self.support_shadow()
        if supported:
            return True
        self.logger.log_important('CET is not defined for the platform.  Skipping module.')
        return False

    def get_cpuid_value(self) -> None:
        (_, _, self.cpuid_7_0__ecx_val, _) = self.cs.cpu.cpuid(7, 0)

    def support_shadow(self) -> bool:
        if self.cpuid_7_0__ecx_val is None:
            self.get_cpuid_value()
        return self.cpuid_7_0__ecx_val & BIT7 != 0

    def support_ibt(self) -> bool:
        if self.cpuid_7_0__ecx_val is None:
            self.get_cpuid_value()
        return self.cpuid_7_0__ecx_val & BIT20 != 0

    def setting_enabled(self, msr_val, field, mask, desc):
        enabled = all((i & mask) != 0 for i in msr_val)
        part_enabled = any((i & mask) != 0 for i in msr_val)
        if enabled:
            self.logger.log(f'  {field}: {desc} is ENABLED')
        elif part_enabled:
            self.logger.log(f'  {field}: {desc} is ENABLED on 1 or more threads')
        else:
            self.logger.log(f'  {field}: {desc} is NOT ENABLED')

    def print_cet_state(self, cet_msr):
        fields = ['SH_STK_EN',
                  'WR_SHSTK_EN',
                  'ENDBR_EN',
                  'LEG_IW_EN',
                  'NO_TRACK_EN',
                  'SUPPRESS_DIS',
                  'SUPPRESS']
        try:
            msr_vals = self.cs.register.read_all(cet_msr)
            reg = self.cs.register.get_def(cet_msr)
            self.logger.log(f'{cet_msr} Settings:')
            for key in fields:
                mask = self.cs.register.get_field_mask(cet_msr, key, True)
                desc = reg['FIELDS'][key]['desc']
                self.setting_enabled(msr_vals, key, mask, desc)
        except HWAccessViolationError:
            self.logger.log(f'Unable to read {cet_msr}')

    def check_cet(self):
        if self.support_shadow():
            self.logger.log("CET Shadow Stack is supported")
        else:
            self.logger.log("CET Shadow Stack is unsupported")
        if self.support_ibt():
            self.logger.log("CET Indirect Branch Tracking is supported")
        else:
            self.logger.log("CET Indirect Branch Tracking is unsupported")
        if self.cs.register.is_defined("IA32_U_CET") and self.cs.register.is_defined("IA32_S_CET"):
            self.print_cet_state("IA32_U_CET")
            self.print_cet_state('IA32_S_CET')
        
        self.result.setStatusBit(self.result.status.INFORMATION)
        self.res = self.result.getReturnCode(ModuleResult.INFORMATION)

    def run(self, module_argv):
        self.logger.start_test("Checking CET Settings")
        self.check_cet()
        return self.res
