#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2018, Eclypsium, Inc.
#Copyright (c) 2019, Intel Corporation
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

########################################################################################################
#
# Main module functionality
#
########################################################################################################

class memlock(chipsec.module_common.BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.res = ModuleResult.NOTAPPLICABLE

    def is_supported(self):
        # Workaround for Atom based processors.  Accessing this MSR on these systems
        # causes a GP fault and can't be caught in UEFI Shell.
        if self.cs.get_chipset_id() not in chipsec.chipset.CHIPSET_FAMILY_ATOM:
            if self.cs.is_register_defined( 'MSR_LT_LOCK_MEMORY' ):
                return self.cs.register_has_field( 'MSR_LT_LOCK_MEMORY', 'LT_LOCK' )
        return False

    def check_MSR_LT_LOCK_MEMORY( self ):
        self.logger.log( "[X] Checking MSR_LT_LOCK_MEMORY status" )
        status = False
        for tid in range(self.cs.msr.get_cpu_thread_count()):
                lt_lock_msr = 0
                try:
                    lt_lock_msr = self.cs.read_register( 'MSR_LT_LOCK_MEMORY', tid )
                except chipsec.helper.oshelper.HWAccessViolationError:
                    self.logger.error( "couldn't read MSR_LT_LOCK_MEMORY" )
                    break
                lt_lock = self.cs.get_register_field( 'MSR_LT_LOCK_MEMORY', lt_lock_msr, 'LT_LOCK' )
                self.logger.log( "[*]   cpu{:d}: MSR_LT_LOCK_MEMORY[LT_LOCK] = {:x}".format(tid, lt_lock) )
                if 0 == lt_lock:
                    status = True
        return status

    def run( self, module_argv ):
        self.res = ModuleResult.PASSED
        self.logger.start_test( "Check MSR_LT_LOCK_MEMORY" )
        check_MSR_LT_LOCK_MEMORY_test_fail = self.check_MSR_LT_LOCK_MEMORY()

        if check_MSR_LT_LOCK_MEMORY_test_fail == True:
            self.logger.log_failed_check( "Check failed. MSR_LT_LOCK_MEMORY isn't configured correctly" )
            self.res = ModuleResult.FAILED
        else:
            self.logger.log_passed_check('Check have successfully passed')
            self.res = ModuleResult.PASSED

        return self.res
