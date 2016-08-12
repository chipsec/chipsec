#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2016, Intel Corporation
# 
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; Version 2.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#Contact information:
#chipsec@intel.com
#

"""
Checks for SPI Controller Flash Descriptor Security Override Pin Strap (FDOPSS). On some systems, this may be routed to a jumper on the motherboard. 
"""

from chipsec.module_common import *
TAGS = [MTAG_BIOS]

class spi_fdopss(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        return True

    def check_fd_security_override_strap(self):
        self.logger.start_test( "SPI Flash Descriptor Security Override Pin-Strap" )

        if not chipsec.chipset.is_register_defined( self.cs, 'HSFS' ):
            self.logger.error( "Couldn't find definition of required configuration registers (HSFS)" )
            return ModuleResult.ERROR

        hsfs_reg = chipsec.chipset.read_register( self.cs, 'HSFS' )
        chipsec.chipset.print_register( self.cs, 'HSFS', hsfs_reg )
        fdopss = chipsec.chipset.get_register_field( self.cs, 'HSFS', hsfs_reg, 'FDOPSS' )

        if 0 != fdopss:
            self.logger.log_passed_check( "SPI Flash Descriptor Security Override is disabled" )
            return ModuleResult.PASSED
        else:
            self.logger.log_failed_check( "SPI Flash Descriptor Security Override is enabled" )
            return ModuleResult.FAILED

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        return self.check_fd_security_override_strap()
