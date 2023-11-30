# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2020, Intel Corporation
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
The configuration of the SPI controller, including protected ranges (PR0-PR4), is locked by HSFS[FLOCKDN] until reset.
If not locked, the controller configuration may be bypassed by reprogramming these registers.

This vulnerability (not setting FLOCKDN) is also checked by other tools, including  `flashrom <http://www.flashrom.org/>`_
and Copernicus by MITRE.

This module checks that the SPI Flash Controller configuration is locked.

Reference:
    - `flashrom <http://www.flashrom.org/>`_
    - `Copernicus: Question Your Assumptions about BIOS Security <http://www.mitre.org/capabilities/cybersecurity/overview/cybersecurity-blog/copernicus-question-your-assumptions-about>`_

Usage:
    ``chipsec_main -m common.spi_lock``

Examples:
    >>> chipsec_main.py -m common.spi_lock

Registers used:
    - FlashLockDown (control)
    - SpiWriteStatusDis (control)

"""

from chipsec.module_common import BaseModule, ModuleResult, MTAG_BIOS
from typing import List

TAGS = [MTAG_BIOS]


class spi_lock(BaseModule):

    def __init__(self):
        super(spi_lock, self).__init__()
        self.rc_res = ModuleResult(0xf73c7bd, 'https://chipsec.github.io/modules/chipsec.modules.common.spi_lock.html')

    def is_supported(self) -> bool:
        if self.cs.is_control_defined('FlashLockDown'):
            return True
        self.rc_res.setStatusBit(self.rc_res.status.NOT_APPLICABLE)
        self.res = self.rc_res.getReturnCode(ModuleResult.NOTAPPLICABLE)
        self.logger.log_important('FlashLockDown control not define for platform.  Skipping module.')
        return False

    def check_spi_lock(self) -> int:
        res = ModuleResult.PASSED
        reg_print = True
        if self.cs.is_control_defined('SpiWriteStatusDis'):
            wrsdis = self.cs.get_control('SpiWriteStatusDis', with_print=reg_print)
            if 1 == wrsdis:
                self.logger.log_good('SPI write status disable set.')
            else:
                res = ModuleResult.FAILED
                self.rc_res.setStatusBit(self.rc_res.status.ACCESS_RW)
                self.logger.log_bad('SPI write status disable not set.')
            reg_print = False

        flockdn = self.cs.get_control('FlashLockDown', with_print=reg_print)
        if 1 == flockdn:
            self.logger.log_good("SPI Flash Controller configuration is locked")
        else:
            res = ModuleResult.FAILED
            self.rc_res.setStatusBit(self.rc_res.status.LOCKS)
            self.logger.log_bad("SPI Flash Controller configuration is not locked")
        reg_print = False

        if res == ModuleResult.FAILED:
            self.logger.log_failed("SPI Flash Controller not locked correctly.")
        elif res == ModuleResult.PASSED:
            self.logger.log_passed("SPI Flash Controller locked correctly.")
        else:
            self.logger.log_warning("Unable to determine if SPI Flash Controller is locked correctly.")

        return self.rc_res.getReturnCode(res)

    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test("SPI Flash Controller Configuration Locks")
        self.res = self.check_spi_lock()
        return self.res
