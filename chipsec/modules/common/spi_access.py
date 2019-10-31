#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2017, Intel Corporation
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
#
# Authors:
#  Yuriy Bulygin
#  Erik Bjorge
#



"""
Checks SPI Flash Region Access Permissions programmed in the Flash Descriptor
"""

from chipsec.module_common import *
TAGS = [MTAG_BIOS]

from chipsec.hal import spi

class spi_access(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.spi    = spi.SPI( self.cs )

    def is_supported(self):
        return True

    ##
    # Displays the SPI Regions Access Permissions
    def check_flash_access_permissions(self):

        res = ModuleResult.PASSED
        frap = self.cs.read_register( 'FRAP' )
        brra = self.cs.get_register_field( 'FRAP', frap, 'BRRA' )
        brwa = self.cs.get_register_field( 'FRAP', frap, 'BRWA' )
        if self.cs.is_register_defined('FDOC') and self.cs.is_register_defined('FDOD'):
            self.cs.write_register('FDOC', 0x3000)
            tmp_reg = self.cs.read_register('FDOD')
            brra |= ((tmp_reg >> 8) & 0xFFF)
            brwa |= ((tmp_reg >> 20) & 0xFFF)

        # Informational
        # CPU/Software access to Platform Data region (platform specific)
        if brwa & (1 << spi.PLATFORM_DATA):
            self.logger.log("[*] Software has write access to Platform Data region in SPI flash (it's platform specific)")

        # Warnings
        # CPU/Software access to GBe region
        if brwa & (1 << spi.GBE):
            res = ModuleResult.WARNING
            self.logger.log_warning("Software has write access to GBe region in SPI flash")

        # Failures
        # CPU/Software access to Flash Descriptor region (Read Only)
        if brwa & (1 << spi.FLASH_DESCRIPTOR):
            res = ModuleResult.FAILED
            self.logger.log_bad("Software has write access to SPI flash descriptor")

        # CPU/Software access to Intel ME region (Read Only)
        if brwa & (1 << spi.ME):
            res = ModuleResult.FAILED
            self.logger.log_bad("Software has write access to Management Engine (ME) region in SPI flash")

        if   ModuleResult.PASSED  == res: self.logger.log_passed_check("SPI Flash Region Access Permissions in flash descriptor look ok")
        elif ModuleResult.FAILED  == res: self.logger.log_failed_check("SPI Flash Region Access Permissions are not programmed securely in flash descriptor")
        elif ModuleResult.WARNING == res: self.logger.log_warn_check("Certain SPI flash regions are writeable by software")

        return res

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        self.logger.start_test( "SPI Flash Region Access Control" )
        self.spi.display_SPI_Ranges_Access_Permissions()
        self.res = self.check_flash_access_permissions()
        return self.res
