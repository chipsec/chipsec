# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2019, Intel Corporation
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
Tests that IA-32/IA-64 architectural features are configured and locked, including IA32 Model Specific Registers (MSRs)

Reference:
    - Intel 64 and IA-32 Architectures Software Developer Manual (SDM)
        - https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html

Usage:
    ``chipsec_main -m common.ia32cfg``

Examples:
    >>> chipsec_main.py -m common.ia32cfg

Registers used:
    - IA32_FEATURE_CONTROL
    - Ia32FeatureControlLock (control)

"""

from chipsec.module_common import BaseModule, ModuleResult, MTAG_HWCONFIG


TAGS = [MTAG_HWCONFIG]


class ia32cfg(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)
        self.res = ModuleResult.PASSED

    def is_supported(self):
        if self.cs.is_register_defined('IA32_FEATURE_CONTROL'):
            if self.cs.is_control_defined('Ia32FeatureControlLock'):
                return True
            self.logger.log_important('Ia32FeatureControlLock control not defined for platform.  Skipping module.')
        else:
            self.logger.log_important('IA32_FEATURE_CONTROL register not defined for platform.  Skipping module.')
        self.res = ModuleResult.NOTAPPLICABLE
        return False

    def check_ia32feature_control(self):
        self.logger.log("[*] Verifying IA32_Feature_Control MSR is locked on all logical CPUs..")

        res = ModuleResult.PASSED
        for tid in range(self.cs.msr.get_cpu_thread_count()):
            if self.logger.VERBOSE:
                feature_cntl = self.cs.read_register('IA32_FEATURE_CONTROL', tid)
                self.cs.print_register('IA32_FEATURE_CONTROL', feature_cntl)
            feature_cntl_lock = self.cs.get_control('Ia32FeatureControlLock', tid)
            self.logger.log("[*] cpu{:d}: IA32_FEATURE_CONTROL Lock = {:d}".format(tid, feature_cntl_lock))
            if 0 == feature_cntl_lock:
                res = ModuleResult.FAILED

        if res == ModuleResult.PASSED:
            self.logger.log_passed("IA32_FEATURE_CONTROL MSR is locked on all logical CPUs")
        else:
            self.logger.log_failed("IA32_FEATURE_CONTROL MSR is not locked on all logical CPUs")

        return res

    def run(self, module_argv):
        self.logger.start_test("IA32 Feature Control Lock")
        self.res = self.check_ia32feature_control()
        return self.res
