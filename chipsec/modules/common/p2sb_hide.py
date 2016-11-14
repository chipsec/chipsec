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
P2SB device is to be hidden by the BIOS before PCI enumeration step.
After post, the unhiding should be done within SMM only to prevent OS from seeing it. 
"""
from chipsec.module_common import *
TAGS = [MTAG_BIOS]

class p2sb_hide(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        if not chipsec.chipset.is_register_defined(self.cs, 'P2SBC'):
            self.logger.error( "Couldn't find definition of required configuration registers" )
            return False
        else:
            return True

    def check_p2sb_hide(self):
        self.logger.start_test( "Primary to Sideband bridge Hide" )

        p2sb_hide_res = ModuleResult.FAILED
        p2sb_hide_val = chipsec.chipset.get_control(self.cs, 'P2sbHide', with_print=True)

        if 1 == p2sb_hide_val:
            p2sb_hide_res = ModuleResult.PASSED
            self.logger.log_passed_check( "Primary to Sideband Bridge is hided" )
        else:
            self.logger.log_failed_check( "Primary to Sideband Bridge is not hided" )

        return p2sb_hide_res

    def run( self, module_argv ):
        return self.check_p2sb_hide()
