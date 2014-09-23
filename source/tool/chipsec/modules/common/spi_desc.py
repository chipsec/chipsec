#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2014, Intel Corporation
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



## \addtogroup modules
# __chipsec/modules/common/spi_desc.py__ -  checks SPI Flash Region Access Permissions programmed in the Flash Descriptor



from chipsec.module_common import *
TAGS = [MTAG_BIOS]

from chipsec.hal.spi import *


class spi_desc(BaseModule):
    
    def __init__(self):
        BaseModule.__init__(self)
        self.spi    = SPI( self.cs )

    def is_supported(self):
        # TODO: temporarily disabled SNB due to hang
        if self.cs.get_chipset_id() not in [chipsec.chipset.CHIPSET_ID_SNB]:
            return True
        return False

    ##
    # Displays the SPI Regions Access Permissions
    def check_flash_access_permissions(self):
        self.logger.start_test( "SPI Flash Region Access Control" )
        #self.spi.display_SPI_Ranges_Access_Permissions()
        self.logger.log('')
    
        ok = True
        frap = self.spi.spi_reg_read(self.cs.Cfg.PCH_RCBA_SPI_FRAP)
        self.logger.log("[*] Software access permissions to SPI flash regions: read = 0x%02X, write = 0x%02X" % (frap&0xF, (frap>>8)&0xF) )
        if (frap&self.cs.Cfg.PCH_RCBA_SPI_FRAP_BRWA_FLASHD != 0):
            ok = False
            self.logger.log_bad("Software has write access to SPI flash descriptor!")
    
        self.logger.log('')
        if ok: self.logger.log_passed_check("SPI flash permissions prevent SW from writing to flash descriptor.")
        else:  self.logger.log_failed_check("SPI flash permissions allow SW to write flash descriptor.")
    
        return ok
    
    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        return self.check_flash_access_permissions()
