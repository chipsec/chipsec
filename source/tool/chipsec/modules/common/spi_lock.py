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
The configuration of the SPI controller, including protected ranges (PR0-PR4), is locked by HSFS[FLOCKDN] until reset. If not locked, the controller configuration may be bypassed by reprogramming these registers. 

This vulnerability (not setting FLOCKDN) is also checked by other tools, including  `flashrom <http://www.flashrom.org/>`_ and `MITRE's Copernicus <http://www.mitre.org/capabilities/cybersecurity/overview/cybersecurity-blog/copernicus-question-your-assumptions-about>`_

This module checks that the SPI Flash Controller configuration is locked.

"""
from chipsec.module_common import *
TAGS = [MTAG_BIOS]

class spi_lock(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        return True

    def check_spi_lock(self):
        self.logger.start_test( "SPI Flash Controller Configuration Lock" )

        spi_lock_res = ModuleResult.FAILED
        hsfs_reg = chipsec.chipset.read_register( self.cs, 'HSFS' )
        chipsec.chipset.print_register( self.cs, 'HSFS', hsfs_reg )
        flockdn = chipsec.chipset.get_register_field( self.cs, 'HSFS', hsfs_reg, 'FLOCKDN' )

        if 1 == flockdn:
            spi_lock_res = ModuleResult.PASSED
            self.logger.log_passed_check( "SPI Flash Controller configuration is locked" )
        else:
            self.logger.log_failed_check( "SPI Flash Controller configuration is not locked" )

        return spi_lock_res

    def run( self, module_argv ):
        return self.check_spi_lock()
