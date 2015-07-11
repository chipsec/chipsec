#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2015, Intel Corporation
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

from chipsec.module_common import *
import chipsec.hal.spi
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
        frap = chipsec.chipset.read_register( self.cs, 'FRAP' )
        chipsec.chipset.print_register( self.cs, 'FRAP', frap )
        brra = chipsec.chipset.get_register_field( self.cs, 'FRAP', frap, 'BRRA' )
        brwa = chipsec.chipset.get_register_field( self.cs, 'FRAP', frap, 'BRWA' )

        self.logger.log("[*] Software access to SPI flash regions: read = 0x%02X, write = 0x%02X" % (brra, brwa) )
        if brwa & (1 << chipsec.hal.spi.FLASH_DESCRIPTOR):
            res = ModuleResult.FAILED
            self.logger.log_bad("Software has write access to SPI flash descriptor")

        self.logger.log('')
        if   ModuleResult.PASSED == res: self.logger.log_passed_check("SPI flash permissions prevent SW from writing to flash descriptor")
        elif ModuleResult.FAILED == res: self.logger.log_failed_check("SPI flash permissions allow SW to write flash descriptor")
        return res

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        return self.check_flash_access_permissions()
