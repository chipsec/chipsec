# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2018, Eclypsium, Inc.
# Copyright (c) 2019-2021, Intel Corporation
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
    - https://github.com/coreboot/coreboot/blob/master/src/cpu/intel/model_206ax/finalize.c
    - https://github.com/coreboot/coreboot/blob/master/src/soc/intel/broadwell/include/soc/msr.h

This module checks the following:
- MSR_LT_LOCK_MEMORY MSR (0x2E7) - Bit [0]

The module returns the following results:
    - **FAILED** : MSR_LT_LOCK_MEMORY[0] is not set
    - **PASSED** : MSR_LT_LOCK_MEMORY[0] is set
    - **ERROR**  : Problem reading MSR_LT_LOCK_MEMORY values

Usage:
  ``chipsec_main -m common.memlock``

Example:
    >>> chipsec_main.py -m common.memlock

Registers used:
    - MSR_LT_LOCK_MEMORY

.. note::
    - This module will not run on Atom based platforms.

"""

from chipsec.module_common import BaseModule, ModuleResult
from chipsec.exceptions import HWAccessViolationError

_MODULE_NAME = 'memlock'


class memlock(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.is_read_error = False

    def is_supported(self):
        # Workaround for Atom based processors.  Accessing this MSR on these systems
        # causes a GP fault and can't be caught in UEFI Shell.
        if not self.cs.is_atom():
            if self.cs.register_has_field('MSR_LT_LOCK_MEMORY', 'LT_LOCK'):
                return True
            else:
                self.logger.log_important("'MSR_LT_LOCK_MEMORY.LT_LOCK' not defined for platform.  Skipping module.")
        else:
            self.logger.log_important('Found an Atom based platform.  Skipping module.')
        self.res = ModuleResult.NOTAPPLICABLE
        return False

    def check_MSR_LT_LOCK_MEMORY(self):
        self.logger.log('[*] Checking MSR_LT_LOCK_MEMORY status')
        status = False
        for tid in range(self.cs.msr.get_cpu_thread_count()):
            lt_lock_msr = 0
            try:
                lt_lock_msr = self.cs.read_register('MSR_LT_LOCK_MEMORY', tid)
            except HWAccessViolationError:
                self.logger.log_important('Could not read MSR_LT_LOCK_MEMORY')
                self.is_read_error = True
                break
            if self.logger.VERBOSE:
                self.cs.print_register('MSR_LT_LOCK_MEMORY', lt_lock_msr)
            lt_lock = self.cs.get_register_field('MSR_LT_LOCK_MEMORY', lt_lock_msr, 'LT_LOCK')
            self.logger.log("[*]   cpu{:d}: MSR_LT_LOCK_MEMORY[LT_LOCK] = {:x}".format(tid, lt_lock))
            if 0 == lt_lock:
                status = True
        return status

    def run(self, module_argv):
        self.logger.start_test("Check MSR_LT_LOCK_MEMORY")
        check_MSR_LT_LOCK_MEMORY_test_fail = self.check_MSR_LT_LOCK_MEMORY()

        if self.is_read_error:
            self.logger.log_error('There was a problem reading MSR_LT_LOCK_MEMORY.')
            self.logger.log_important('Possible the environment or a platform feature is preventing these reads.')
            self.res = ModuleResult.ERROR
        elif check_MSR_LT_LOCK_MEMORY_test_fail == True:
            self.logger.log_failed("MSR_LT_LOCK_MEMORY.LT_LOCK bit is not configured correctly")
            self.res = ModuleResult.FAILED
        else:
            self.logger.log_passed('MSR_LT_LOCK_MEMORY.LT_LOCK bit is set')
            self.res = ModuleResult.PASSED

        return self.res
