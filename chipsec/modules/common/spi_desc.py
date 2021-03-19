#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2021, Intel Corporation
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
The SPI Flash Descriptor indicates read/write permissions for devices to access regions of the flash memory. This module simply reads the Flash Descriptor and checks that software cannot modify the Flash Descriptor itself. If software can write to the Flash Descriptor, then software could bypass any protection defined by it. While often used for debugging, this should not be the case on production systems.

This module checks that software cannot write to the flash descriptor.

"""

from chipsec.module_common import BaseModule, ModuleResult, MTAG_BIOS
from chipsec.hal.spi import FLASH_DESCRIPTOR

TAGS = [MTAG_BIOS]

class spi_desc(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        return True

    ##
    # Displays the SPI Regions Access Permissions
    def check_flash_access_permissions(self):
        self.logger.start_test( "SPI Flash Region Access Control" )

        res = ModuleResult.PASSED
        frap = self.cs.read_register( 'FRAP' )
        self.cs.print_register( 'FRAP', frap )
        brra = self.cs.get_register_field( 'FRAP', frap, 'BRRA' )
        brwa = self.cs.get_register_field( 'FRAP', frap, 'BRWA' )

        self.logger.log("[*] Software access to SPI flash regions: read = 0x{:02X}, write = 0x{:02X}".format(brra, brwa) )
        if brwa & (1 << FLASH_DESCRIPTOR):
            res = ModuleResult.FAILED
            self.logger.log_bad("Software has write access to SPI flash descriptor")

        self.logger.log('')
        if   ModuleResult.PASSED == res:
            self.logger.log_passed("SPI flash permissions prevent SW from writing to flash descriptor")
        elif ModuleResult.FAILED == res:
            self.logger.log_failed("SPI flash permissions allow SW to write flash descriptor")
            self.logger.log_important('System may be using alternative protection by including descriptor region in SPI Protected Range Registers')
        return res

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        self.res = self.check_flash_access_permissions()
        return self.res
