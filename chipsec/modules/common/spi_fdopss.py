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

from chipsec.module_common import BaseModule, ModuleResult, MTAG_BIOS

TAGS = [MTAG_BIOS]


class spi_fdopss(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        if not self.cs.register_has_field('HSFS', 'FDOPSS'):
            self.logger.log_important('HSFS.FDOPSS field not defined for platform.  Skipping module.')
            self.res = ModuleResult.NOTAPPLICABLE
            return False
        return True

    def check_fd_security_override_strap(self):
        hsfs_reg = self.cs.read_register('HSFS')
        self.cs.print_register('HSFS', hsfs_reg)
        fdopss = self.cs.get_register_field('HSFS', hsfs_reg, 'FDOPSS')

        if (fdopss != 0):
            self.logger.log_passed("SPI Flash Descriptor Security Override is disabled")
            return ModuleResult.PASSED
        else:
            self.logger.log_failed("SPI Flash Descriptor Security Override is enabled")
            return ModuleResult.FAILED

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run(self, module_argv):
        self.logger.start_test("SPI Flash Descriptor Security Override Pin-Strap")
        self.res = self.check_fd_security_override_strap()
        return self.res
