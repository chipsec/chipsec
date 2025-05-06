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

from chipsec.module_common import BaseModule, CPU
from chipsec.library.returncode import ModuleResult
from chipsec.library.defines import BIT7, BIT20
from chipsec.library.exceptions import HWAccessViolationError
from chipsec.library.register import ObjList

TAGS = [CPU]
METADATA_TAGS = ['OPENSOURCE', 'IA', 'COMMON', 'CET']


class cet(BaseModule):
    def __init__(self):
        super(cet, self).__init__()
        self.cpuid_7_0__ecx_val = None
        self.cs.set_scope({
            None: "8086.MSR"
        })

    def is_supported(self) -> bool:
        supported = self.support_shadow()
        if supported:
            return True
        self.logger.log_important('CET is not defined for the platform.  Skipping module.')
        return False

    def get_cpuid_value(self) -> None:
        (_, _, self.cpuid_7_0__ecx_val, _) = self.cs.hals.CPU.cpuid(7, 0)

    def support_shadow(self) -> bool:
        if self.cpuid_7_0__ecx_val is None:
            self.get_cpuid_value()
        return self.cpuid_7_0__ecx_val & BIT7 != 0

    def support_ibt(self) -> bool:
        if self.cpuid_7_0__ecx_val is None:
            self.get_cpuid_value()
        return self.cpuid_7_0__ecx_val & BIT20 != 0

    def setting_enabled(self, msr_obj: ObjList, field: str, desc: str) -> None:
        enabled = msr_obj.is_all_field_value(1, field)
        part_enabled = msr_obj.is_any_field_value(1, field)
        if enabled:
            self.logger.log(f'  {field}: {desc} is ENABLED')
        elif part_enabled:
            self.logger.log(f'  {field}: {desc} is ENABLED on 1 or more threads')
        else:
            self.logger.log(f'  {field}: {desc} is NOT ENABLED')

    def print_cet_state(self, cet_msr) -> None:
        fields = ['SH_STK_EN',
                  'WR_SHSTK_EN',
                  'ENDBR_EN',
                  'LEG_IW_EN',
                  'NO_TRACK_EN',
                  'SUPPRESS_DIS',
                  'SUPPRESS']
        try:
            msr_objs = self.cs.register.get_list_by_name(cet_msr)
            reg_def = self.cs.register.get_def(cet_msr)
            self.logger.log(f'{cet_msr} Settings:')
            for key in fields:
                desc = reg_def.fields[key]['desc']
                self.setting_enabled(msr_objs, key, desc)
        except HWAccessViolationError:
            self.logger.log(f'Unable to read {cet_msr}')

    def check_cet(self) -> None:
        if self.support_shadow():
            self.logger.log('CET Shadow Stack is supported')
        else:
            self.logger.log('CET Shadow Stack is unsupported')
        if self.support_ibt():
            self.logger.log('CET Indirect Branch Tracking is supported')
        else:
            self.logger.log('CET Indirect Branch Tracking is unsupported')
        if self.cs.register.is_defined('IA32_U_CET') and self.cs.register.is_defined('IA32_S_CET'):
            self.print_cet_state('IA32_U_CET')
            self.print_cet_state('IA32_S_CET')

        self.result.setStatusBit(self.result.status.INFORMATION)
        self.res = self.result.getReturnCode(ModuleResult.INFORMATION)

    def run(self, module_argv):
        self.logger.start_test('Checking CET Settings')
        self.check_cet()
        return self.res
