# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2018, Eclypsium, Inc.
# Copyright (c) 2018-2021, Intel Corporation
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

"""
This module checks if the system has debug features turned on,
specifically the Direct Connect Interface (DCI).

This module checks the following bits:
1. HDCIEN bit in the DCI Control Register
2. Debug enable bit in the IA32_DEBUG_INTERFACE MSR
3. Debug lock bit in the IA32_DEBUG_INTERFACE MSR
4. Debug occurred bit in the IA32_DEBUG_INTERFACE MSR

Usage:
    ``chipsec_main -m common.debugenabled``

Examples:
    >>> chipsec_main.py -m common.debugenabled

The module returns the following results:
    - **FAILED** : Any one of the debug features is enabled or unlocked.
    - **PASSED** : All debug feature are disabled and locked.

Registers used:
    - IA32_DEBUG_INTERFACE[DEBUGENABLE]
    - IA32_DEBUG_INTERFACE[DEBUGELOCK]
    - IA32_DEBUG_INTERFACE[DEBUGEOCCURED]
    - P2SB_DCI.DCI_CONTROL_REG[HDCIEN]

"""

from chipsec.module_common import BaseModule, CPU
from chipsec.library.returncode import ModuleResult
from chipsec.library.defines import BIT11
from typing import List

TAGS = [CPU]
METADATA_TAGS = ['OPENSOURCE', 'IA', 'COMMON', 'DEBUGENABLED']

_MODULE_NAME = 'debugenabled'


class debugenabled(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.cs.set_scope({
            "ECTRL": "8086.DCI",
            "IA32_DEBUG_INTERFACE": "8086.MSR"
        })
        self.is_enable_set = False
        self.is_debug_set = False
        self.is_lock_set = True

    def is_supported(self) -> bool:
        # Use CPUID Function 1 to determine if the IA32_DEBUG_INTERFACE MSR is supported.
        # See IA32 SDM CPUID Instruction for details.  (SDBG ECX bit 11)
        (_, _, ecx, _) = self.cs.hals.cpu.cpuid(1, 0)
        supported = (ecx & BIT11) != 0
        if not supported and not self.cs.register.is_defined('ECTRL'):
            self.logger.log_important('CPU Debug features are not supported on this platform.  Skipping module.')
        return supported

    def check_dci(self) -> int:
        TestFail = ModuleResult.PASSED
        self.logger.log('')
        self.logger.log('[*] Checking DCI register status')
        ectrl = self.cs.register.get_list_by_name('ECTRL')
        ectrl.read_and_verbose_print()
        hdcien_mask = ectrl[0].get_field_mask('ENABLE', True)

        if ectrl.is_all_field_value(ectrl[0].get_field('ENABLE'), 'ENABLE'):
            self.logger.log_good('CPU debug enable is set consistently')
        if ectrl.is_any_value(hdcien_mask, 'ENABLE'):
            self.logger.log_bad('DCI Debug is enabled')
            TestFail = ModuleResult.FAILED
            self.result.setStatusBit(self.result.status.DEBUG_FEATURE)
        else:
            self.logger.log_good('DCI Debug is disabled')
        return TestFail

    def check_cpu_debug_enable(self) -> int:
        self.logger.log('')
        self.logger.log('[*] Checking IA32_DEBUG_INTERFACE MSR status')
        TestFail = ModuleResult.PASSED
        dbg_regs = self.cs.register.get_list_by_name('IA32_DEBUG_INTERFACE')
        dbg_regs.read_and_verbose_print()


        if dbg_regs.is_all_field_value(dbg_regs[0].get_field('ENABLE'), 'ENABLE'):
            self.logger.log_good('CPU debug enable is set consitently')
        if dbg_regs.is_any_field_value(1, 'ENABLE'):
            self.logger.log_bad('CPU debug enable requested by software.')
            self.is_enable_set = True
            TestFail = ModuleResult.FAILED
            self.result.setStatusBit(self.result.status.DEBUG_FEATURE)
        if dbg_regs.is_all_field_value(dbg_regs[0].get_field('LOCK'), 'LOCK'):
            self.logger.log_good('CPU debug lock is set consitently')
        if dbg_regs.is_any_field_value(0, 'LOCK'):
            self.logger.log_bad('CPU debug interface is not locked.')
            self.is_lock_set = False
            TestFail = ModuleResult.FAILED
            self.result.setStatusBit(self.result.status.LOCKS)
        if dbg_regs.is_any_field_value(1, 'DEBUG_OCCURRED'):
            self.logger.log_important('Debug Occurred bit set in IA32_DEBUG_INTERFACE MSR')
            self.is_debug_set = True
            self.result.setStatusBit(self.result.status.DEBUG_FEATURE)
            if TestFail == ModuleResult.PASSED:
                TestFail = ModuleResult.WARNING
        if TestFail == ModuleResult.PASSED:
            self.logger.log_good('CPU debug interface state is correct.')
        return TestFail

    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test('Debug features test')

        cpu_debug_test_fail = self.check_cpu_debug_enable()

        dci_test_fail = ModuleResult.PASSED
        if self.cs.register.is_defined('ECTRL'):
            dci_test_fail = self.check_dci()

        self.logger.log('')
        self.logger.log('[*] Module Results:')

        if self.is_debug_set:
            self.logger.log_important('IA32_DEBUG_INTERFACE.DEBUG_OCCURRED bit is set.')
        if self.is_enable_set:
            self.logger.log_important('IA32_DEBUG_INTERFACE.ENABLE bit is set.')
        if not self.is_lock_set:
            self.logger.log_important('IA32_DEBUG_INTERFACE.LOCK bit is NOT set.')

        if self.cs.control.is_defined('SamplePart'):
            sp = self.cs.control.get_list_by_name('SamplePart')
            if sp.is_all_value(1):
                self.logger.log_passed('CPU is a Sample Part. Test is N/A.')
                self.res = self.result.getReturnCode(ModuleResult.INFORMATION)
                return self.res

        if (dci_test_fail == ModuleResult.FAILED) or (cpu_debug_test_fail == ModuleResult.FAILED):
            self.logger.log_failed('One or more of the debug checks have failed and a debug feature is enabled')
            self.res = self.result.getReturnCode(ModuleResult.FAILED)
        elif (dci_test_fail == ModuleResult.WARNING) or (cpu_debug_test_fail == ModuleResult.WARNING):
            self.logger.log_warning('An unexpected debug state was discovered on this platform')
            self.res = self.result.getReturnCode(ModuleResult.WARNING)
        else:
            self.logger.log_passed('All checks have successfully passed')
            self.res = self.result.getReturnCode(ModuleResult.PASSED)

        return self.res
