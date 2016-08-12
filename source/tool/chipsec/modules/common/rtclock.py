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
Checks for RTC memory locks. Since we do not know what RTC memory will be used for on a specific platform, we return WARNING (rather than FAILED) if the memory is not locked. 
"""

from chipsec.module_common import *

TAGS = [MTAG_BIOS,MTAG_HWCONFIG]


class rtclock(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.res = ModuleResult.PASSED

    def is_supported(self):
        return (self.cs.get_chipset_id() in chipsec.chipset.CHIPSET_FAMILY_CORE)
        
    def check_rtclock(self):
        self.logger.start_test( "Protected RTC memory locations" )

        rc_reg = chipsec.chipset.read_register( self.cs, 'RC' )
        chipsec.chipset.print_register( self.cs, 'RC', rc_reg )
        ll = chipsec.chipset.get_register_field( self.cs, 'RC', rc_reg, 'LL' )
        ul = chipsec.chipset.get_register_field( self.cs, 'RC', rc_reg, 'UL' )

        if ll == 1: self.logger.log_good( "Protected bytes (0x38-0x3F) in low 128-byte bank of RTC memory are locked" )
        else:  self.logger.log_bad( "Protected bytes (0x38-0x3F) in low 128-byte bank of RTC memory are not locked" )
        if ul == 1: self.logger.log_good( "Protected bytes (0x38-0x3F) in high 128-byte bank of RTC memory are locked" )
        else:  self.logger.log_bad( "Protected bytes (0x38-0x3F) in high 128-byte bank of RTC memory are not locked" )

        if ll == 1 and ul == 1:
            self.res = ModuleResult.PASSED
            self.logger.log_passed_check( "Protected locations in RTC memory are locked" )
        else:
            self.res = ModuleResult.WARNING
            self.logger.log_warn_check( "Protected locations in RTC memory are accessible (BIOS may not be using them)" )

        return self.res

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        return self.check_rtclock()
