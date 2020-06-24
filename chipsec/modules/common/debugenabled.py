#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2018, Eclypsium, Inc.
#Copyright (c) 2018-2019, Intel Corporation
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

The module returns the following results:
FAILED : Any one of the debug features is enabled or unlocked.
PASSED : All debug feature are diabled and locked.

Hardware registers used:
IA32_DEBUG_INTERFACE[DEBUGENABLE]
IA32_DEBUG_INTERFACE[DEBUGELOCK]
IA32_DEBUG_INTERFACE[DEBUGEOCCURED]
P2SB_DCI.DCI_CONTROL_REG[HDCIEN]

"""

from chipsec.module_common import BaseModule, ModuleResult
from chipsec.defines import BIT11
_MODULE_NAME = 'debugenabled'

########################################################################################################
#
# Main module functionality
#
########################################################################################################

class debugenabled(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        # Use CPUID Function 1 to determine if the IA32_DEBUG_INTERFACE MSR is supported.
        # See IA32 SDM CPUID Instruction for details.  (SDBG ECX bit 11)
        (eax, ebx, ecx, edx) = self.cs.helper.cpuid( 1, 0 )
        supported = (ecx & BIT11) != 0
        if not supported:
            self.res = ModuleResult.NOTAPPLICABLE
            self.logger.log_skipped_check('CPU Debug features are not supported on this platform')
        return supported

    def check_dci( self ):
        TestFail = ModuleResult.PASSED
        self.logger.log('\n[*] Checking DCI register status')
        ectrl = self.cs.read_register('ECTRL')
        HDCIEN = self.cs.get_register_field('ECTRL', ectrl, 'ENABLE') == 1
        if self.logger.VERBOSE: self.cs.print_register('ECTRL', ectrl)
        if HDCIEN:
            self.logger.log_bad('DCI Debug is enabled')
            TestFail = ModuleResult.FAILED
        else:
            self.logger.log_good('DCI Debug is disabled')
        return TestFail

    def check_cpu_debug_enable( self ):
        self.logger.log('\n[*] Checking IA32_DEBUG_INTERFACE msr status')
        TestFail = ModuleResult.PASSED
        for tid in range(self.cs.msr.get_cpu_thread_count()):
            dbgiface = self.cs.read_register('IA32_DEBUG_INTERFACE', tid)
            IA32_DEBUG_INTERFACE_DEBUGENABLE = self.cs.get_register_field('IA32_DEBUG_INTERFACE', dbgiface, 'ENABLE') == 1
            IA32_DEBUG_INTERFACE_DEBUGELOCK = self.cs.get_register_field('IA32_DEBUG_INTERFACE', dbgiface, 'LOCK') == 1
            IA32_DEBUG_INTERFACE_DEBUGEOCCURED = self.cs.get_register_field('IA32_DEBUG_INTERFACE', dbgiface, 'DEBUG_OCCURRED') == 1
            if self.logger.VERBOSE:
                self.cs.print_register('IA32_DEBUG_INTERFACE', dbgiface)

            if IA32_DEBUG_INTERFACE_DEBUGENABLE:
                self.logger.log_bad("CPU debug enable requested by software.")
                TestFail = ModuleResult.FAILED
            if not IA32_DEBUG_INTERFACE_DEBUGELOCK:
                self.logger.log_bad("CPU debug interface is not locked.")
                TestFail = ModuleResult.FAILED
            if IA32_DEBUG_INTERFACE_DEBUGEOCCURED:
                self.logger.log_warning('Debug Occurred bit set in IA32_DEBUG_INTERFACE MSR')
                if TestFail == ModuleResult.PASSED:
                    TestFail = ModuleResult.WARNING
            if TestFail == ModuleResult.PASSED:
                self.logger.log_good("CPU debug interface state is correct.")
        return TestFail

    def run( self, module_argv ):
        if len(module_argv) > 2:
            self.logger.error('Not expecting any arguments')
            self.res = ModuleResult.ERROR
            return self.res

        self.logger.start_test('Debug features test')

        cpu_debug_test_fail = self.check_cpu_debug_enable()

        dci_test_fail = ModuleResult.PASSED
        if self.cs.is_register_defined('ECTRL'):
            dci_test_fail = self.check_dci()

        self.logger.log("\n[*] Module Result")
        if (dci_test_fail == ModuleResult.FAILED or cpu_debug_test_fail == ModuleResult.FAILED):
            self.logger.log_failed_check('One or more of the debug checks have failed and a debug feature is enabled')
            self.res = ModuleResult.FAILED
        elif (dci_test_fail == ModuleResult.WARNING or cpu_debug_test_fail == ModuleResult.WARNING):
            self.logger.log_warn_check('An unexpected debug state was discovered on this platform')
            self.res = ModuleResult.WARNING
        else:
            self.logger.log_passed_check('All checks have successfully passed')

        return self.res
