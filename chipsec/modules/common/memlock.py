#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2018, Eclypsium, Inc.
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
This module checks if memory configuration is locked to protect SMM

Reference: 
https://github.com/coreboot/coreboot/blob/master/src/cpu/intel/model_206ax/finalize.c
https://github.com/coreboot/coreboot/blob/master/src/soc/intel/broadwell/include/soc/msr.h

This module checks the following:
- MSR_LT_LOCK_MEMORY MSR (0x2E7) - Bit [0]

The module returns the following results:
FAILED : MSR_LT_LOCK_MEMORY[0] is not set
PASSED : MSR_LT_LOCK_MEMORY[0] is set.

Hardware registers used:
MSR_LT_LOCK_MEMORY

"""

from chipsec.module_common import *
import chipsec.chipset
import chipsec.defines
_MODULE_NAME = 'memlock'

MSR_LT_LOCK_MEMORY = 0x2E7

B_MSR_LT_LOCK_MEMORY_MASK = 0b00000000000000000000000000000001

########################################################################################################
#
# Main module functionality
#
########################################################################################################

class memlock(chipsec.module_common.BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        current_platform_id = self.cs.get_chipset_id()
        supported = True
        return supported
        
    def check_MSR_LT_LOCK_MEMORY( self ):
        self.logger.log( "[X] Checking MSR_LT_LOCK_MEMORY status" )
        status = False
        for tid in range(self.cs.msr.get_cpu_thread_count()):
            (eax, edx) = self.cs.helper.read_msr( tid, MSR_LT_LOCK_MEMORY )
            self.logger.log('[cpu%d] RDMSR( 0x%x ): EAX = 0x%08X, EDX = 0x%08X' % (tid, MSR_LT_LOCK_MEMORY, eax, edx) )
            MSR_LT_LOCK_MEMORY_STATE = ((B_MSR_LT_LOCK_MEMORY_MASK & eax) == B_MSR_LT_LOCK_MEMORY_MASK)
            if not MSR_LT_LOCK_MEMORY_STATE: 
                status = True
        return status

    def run( self, module_argv ):
        if len(module_argv) > 2:
            self.logger.error( 'Not expecting any arguments' )
            return ModuleResult.ERROR
        returned_result = ModuleResult.PASSED;
        self.logger.start_test( "[X] Check MSR_LT_LOCK_MEMORY" )
        script_pa = None
        check_MSR_LT_LOCK_MEMORY_test_fail = self.check_MSR_LT_LOCK_MEMORY();
            
        if check_MSR_LT_LOCK_MEMORY_test_fail == True:
            self.logger.log_failed_check( '[X] Check failed. MSR_LT_LOCK_MEMORY doesn\'t configurated correctly' )
            returned_result = ModuleResult.FAILED
        else:
            self.logger.log_passed_check('[X] Check have successfully passed')
            returned_result = ModuleResult.PASSED
       
        return returned_result
