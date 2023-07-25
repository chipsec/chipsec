# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2022, Intel Corporation
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
Checks for RTC memory locks.
Since we do not know what RTC memory will be used for on a specific platform, we return WARNING (rather than FAILED) if the memory is not locked.

Usage:
    ``chipsec_main -m common.rtclock [-a modify]``

    - ``-a modify``: Attempt to modify CMOS values

Examples:
    >>> chipsec_main.py -m common.rtclock
    >>> chipsec_main.py -m common.rtclock -a modify

Registers used:
    - RC.LL
    - RC.UL

.. NOTE::
    - This module will only run on Core platforms
"""

from chipsec.module_common import BaseModule, ModuleResult, MTAG_BIOS, MTAG_HWCONFIG
from chipsec.hal.cmos import CMOS
from chipsec.config import CHIPSET_CODE_AVN
TAGS = [MTAG_BIOS, MTAG_HWCONFIG]


class rtclock(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.cmos = CMOS(self.cs)
        self.user_request = False
        self.test_offset = 0x38
        self.test_value = 0xAA

    def is_supported(self):
        if self.cs.is_core() or (self.cs.Cfg.get_chipset_code() == CHIPSET_CODE_AVN):
            if self.cs.is_register_defined('RC'):
                return True
            self.logger.log_important('RC register not defined for platform.  Skipping module.')
        else:
            self.logger.log_important('Not a Core platform.  Skipping check.')
        self.res = ModuleResult.NOTAPPLICABLE
        return False

    def check_rtclock(self):
        ll = ul = 0
        check_config_regs = self.cs.read_register('RC') != 0xFFFFFFFF

        if check_config_regs:
            rc_reg = self.cs.read_register('RC')
            self.cs.print_register('RC', rc_reg)
            ll = self.cs.get_register_field('RC', rc_reg, 'LL')
            ul = self.cs.get_register_field('RC', rc_reg, 'UL')
        elif self.user_request:
            self.logger.log_important('Writing to CMOS to determine write protection (original values will be restored)')

            # Try to modify the low RTC memory regions.
            original_val = self.cmos.read_cmos_low(self.test_offset)
            self.cmos.write_cmos_low(self.test_offset, original_val ^ self.test_value)
            if original_val == self.cmos.read_cmos_low(self.test_offset):
                ll = 1
            else:
                self.logger.log_important('Restoring original value')
                self.cmos.write_cmos_low(self.test_offset, original_val)

            # Try to modify the upper RTC memory regions.
            original_val = self.cmos.read_cmos_high(self.test_offset)
            self.cmos.write_cmos_high(self.test_offset, original_val ^ self.test_value)
            if original_val == self.cmos.read_cmos_high(self.test_offset):
                ul = 1
            else:
                self.logger.log_important('Restoring original value')
                self.cmos.write_cmos_high(self.test_offset, original_val)
        else:
            self.logger.log_important("Unable to test lock bits without attempting to modify CMOS.")
            self.logger.log("[*] Run chipsec_main manually with the following commandline flags.")
            self.logger.log("[*] python chipsec_main -m common.rtclock -a modify")
            return ModuleResult.WARNING

        if ll == 1:
            self.logger.log_good("Protected bytes (0x38-0x3F) in low 128-byte bank of RTC memory are locked")
        else:
            self.logger.log_bad("Protected bytes (0x38-0x3F) in low 128-byte bank of RTC memory are not locked")
        if ul == 1:
            self.logger.log_good("Protected bytes (0x38-0x3F) in high 128-byte bank of RTC memory are locked")
        else:
            self.logger.log_bad("Protected bytes (0x38-0x3F) in high 128-byte bank of RTC memory are not locked")

        if (ll == 1) and (ul == 1):
            res = ModuleResult.PASSED
            self.logger.log_passed("Protected locations in RTC memory are locked")
        else:
            res = ModuleResult.WARNING
            self.logger.log_warning("Protected locations in RTC memory are accessible (BIOS may not be using them)")

        return res

    def run(self, module_argv):
        self.logger.start_test("Protected RTC memory locations")

        if len(module_argv) >= 1:
            if module_argv[0].lower() == 'modify':
                self.user_request = True
        self.res = self.check_rtclock()
        return self.res
