# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
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
Checks for SPI Controller Flash Descriptor Security Override Pin Strap (FDOPSS). 
On some systems, this may be routed to a jumper on the motherboard. 

Usage:
    ``chipsec_main -m common.spi_fdopss``

Examples:
    >>> chipsec_main.py -m common.spi_fdopss

Registers used:
    - HSFS.FDOPSS

"""

from chipsec.library.exceptions import CSReadError
from chipsec.module_common import BaseModule, MTAG_BIOS
from chipsec.library.returncode import ModuleResult
from typing import List

TAGS = [MTAG_BIOS]


class spi_fdopss(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self) -> bool:
        if not self.cs.register.has_field('HSFS', 'FDOPSS'):
            self.logger.log_important('HSFS.FDOPSS field not defined for platform.  Skipping module.')
            return False
        return True

    def check_fd_security_override_strap(self) -> int:
        hsfs_reg = self.cs.register.read('HSFS')
        self.cs.register.print('HSFS', hsfs_reg)
        fdopss = self.cs.register.get_field('HSFS', hsfs_reg, 'FDOPSS')

        if (fdopss != 0):
            self.logger.log_passed("SPI Flash Descriptor Security Override is disabled")
            return self.result.getReturnCode(ModuleResult.PASSED)
        else:
            self.logger.log_failed("SPI Flash Descriptor Security Override is enabled")
            self.result.setStatusBit(self.result.status.CONFIGURATION)
            return self.result.getReturnCode(ModuleResult.FAILED)

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test("SPI Flash Descriptor Security Override Pin-Strap")
        try:
            self.res = self.check_fd_security_override_strap()
        except CSReadError as err:
            self.logger.log_warning(f"Unable to read register: {err}")
            self.result.setStatusBit(self.result.status.VERIFY)
            self.res = self.result.getReturnCode(ModuleResult.WARNING)
        return self.res
