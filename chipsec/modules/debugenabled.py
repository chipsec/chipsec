#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2018, Eclypsium, Inc.
#Copyright (c) 2018, Intel Corporation
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

from chipsec.module_common import *
import chipsec.chipset
import chipsec.defines
_MODULE_NAME = 'debugenabled'


import chipsec.hal.uefi
import chipsec.hal.uefi_common

EDX_ENABLE_STATE = 0x00000000
IA32_DEBUG_INTERFACE_MSR = 0xC80
P2SB_DCI_PORT_ID = 0xB8
DCI_CONTROL_REG_OFFSET = 0x4

HDCIEN_MASK = 0b00000000000000000000000000010000
IA32_DEBUG_INTERFACE_DEBUGENABLE_MASK = 0b00000000000000000000000000000001
IA32_DEBUG_INTERFACE_DEBUGELOCK_MASK = 0b01000000000000000000000000000000
IA32_DEBUG_INTERFACE_DEBUGEOCCURED_MASK = 0b10000000000000000000000000000000

CPUID_IA32_DEBUG_INTERFACE_SUPPORTED_BIT11_MASK = 0b00000000000000000000100000000000

########################################################################################################
#
# Main module functionality
#
########################################################################################################

class debugenabled(chipsec.module_common.BaseModule):



    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        (eax, ebx, ecx, edx) = self.cs.helper.cpuid( 1, 0 )
        supported = (ecx & CPUID_IA32_DEBUG_INTERFACE_SUPPORTED_BIT11_MASK == CPUID_IA32_DEBUG_INTERFACE_SUPPORTED_BIT11_MASK)
        if not supported: self.logger.log_skipped_check('CPU Debug features are not supported on this platform')
        return supported


    def check_dci( self ):
        TestFail = ModuleResult.PASSED
        self.logger.log('[X] Checking DCI register status')
        value = self.cs.msgbus.mm_msgbus_reg_read(P2SB_DCI_PORT_ID,DCI_CONTROL_REG_OFFSET)
        if self.logger.VERBOSE: self.logger.log('[*] DCI Control Register = 0x%X' % value )
        HDCIEN = ((value & HDCIEN_MASK) == HDCIEN_MASK)
        if HDCIEN:
            TestFail = ModuleResult.FAILED
        return TestFail

    def check_cpu_debug_enable( self ):
        self.logger.log('[X] Checking IA32_DEBUG_INTERFACE msr status')
        TestFail = ModuleResult.PASSED
        for tid in range(self.cs.msr.get_cpu_thread_count()):
            (eax, edx) = self.cs.helper.read_msr( tid, IA32_DEBUG_INTERFACE_MSR )
            if self.logger.VERBOSE: self.logger.log('[cpu%d] RDMSR( 0x%x ): EAX = 0x%08X, EDX = 0x%08X' % (tid, IA32_DEBUG_INTERFACE_MSR, eax, edx) )
            IA32_DEBUG_INTERFACE_DEBUGENABLE = ((IA32_DEBUG_INTERFACE_DEBUGENABLE_MASK & eax) == IA32_DEBUG_INTERFACE_DEBUGENABLE_MASK)
            IA32_DEBUG_INTERFACE_DEBUGELOCK = not ((IA32_DEBUG_INTERFACE_DEBUGELOCK_MASK & eax) == IA32_DEBUG_INTERFACE_DEBUGELOCK_MASK)
            IA32_DEBUG_INTERFACE_DEBUGEOCCURED = ((IA32_DEBUG_INTERFACE_DEBUGEOCCURED_MASK & eax) == IA32_DEBUG_INTERFACE_DEBUGEOCCURED_MASK)
            if edx == EDX_ENABLE_STATE: #Sanity check only EAX matters
                if (IA32_DEBUG_INTERFACE_DEBUGENABLE) or (IA32_DEBUG_INTERFACE_DEBUGELOCK):
                    if self.logger.VERBOSE:
                        self.logger.log('IA32_DEBUG_INTERFACE_DEBUGENABLE ==' + str(IA32_DEBUG_INTERFACE_DEBUGENABLE))
                        self.logger.log('IA32_DEBUG_INTERFACE_DEBUGELOCK ==' + str(IA32_DEBUG_INTERFACE_DEBUGELOCK))
                        self.logger.log('IA32_DEBUG_INTERFACE_DEBUGEOCCURED ==' + str(IA32_DEBUG_INTERFACE_DEBUGEOCCURED))
                    TestFail = ModuleResult.FAILED
                if IA32_DEBUG_INTERFACE_DEBUGEOCCURED:
                        TestFail = ModuleResult.WARNING
        return TestFail

    def run( self, module_argv ):
        if len(module_argv) > 2:
            self.logger.error('Not expecting any arguments')
            return ModuleResult.ERROR
        returned_result = ModuleResult.PASSED
        self.logger.start_test('Debug features test')
        script_pa = None
        dci_test_fail = ModuleResult.PASSED
        cpu_debug_test_fail = ModuleResult.PASSED

        cpu_debug_test_fail = self.check_cpu_debug_enable()
        if (cpu_debug_test_fail == ModuleResult.FAILED):
            self.logger.log_bad('CPU IA32_DEBUG_INTERFACE is enabled')
        elif cpu_debug_test_fail == ModuleResult.WARNING:
            self.logger.log_warning('Debug Occured bit set in IA32_DEBUG_INTERFACE msr')
        else:
            self.logger.log_good('CPU IA32_DEBUG_INTERFACE is disabled')

        current_platform_id = self.cs.get_chipset_id()
        dci_supported = (current_platform_id == chipsec.chipset.CHIPSET_ID_CFL) or (current_platform_id == chipsec.chipset.CHIPSET_ID_KBL) or (current_platform_id == chipsec.chipset.CHIPSET_ID_SKL)
        if (dci_supported):
            dci_test_fail = self.check_dci()
            if (dci_test_fail == ModuleResult.FAILED):
                self.logger.log_bad('DCI Debug is enabled')
            else:
                self.logger.log_good('DCI Debug is disabled')

        if (dci_test_fail == ModuleResult.FAILED or cpu_debug_test_fail == ModuleResult.FAILED):
            self.logger.log_failed_check('One or more of the debug checks have failed and a debug feature is enabled')
            returned_result = ModuleResult.FAILED
        elif (dci_test_fail == ModuleResult.WARNING or cpu_debug_test_fail == ModuleResult.WARNING):
            self.logger.log_warn_check('An unexpected debug state was discovered on this platform')
            returned_result = ModuleResult.WARNING
        else:
            self.logger.log_passed_check('All checks have successfully passed')
            returned_result = ModuleResult.PASSED

        return returned_result
