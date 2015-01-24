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




## \addtogroup modules
# __chipsec/modules/common/smm.py__ - common checks for protection of compatible System Management Mode (SMM) memory (SMRAM)
#
from collections import namedtuple
from chipsec.module_common import *
TAGS = [MTAG_BIOS,MTAG_SMM]

class smm(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        chipset = self.cs.get_chipset_id()
        return (chipset not in chipsec.chipset.CHIPSET_FAMILY_ATOM) and (chipset not in chipsec.chipset.CHIPSET_FAMILY_XEON)
  
    def check_SMRAMC(self):
        self.logger.start_test( "Compatible SMM memory (SMRAM) Protection" )
        
        if not chipsec.chipset.is_register_defined( self.cs, 'PCI0.0.0_SMRAMC'  ) :
            self.logger.error( "Couldn't find definition of required registers (PCI0.0.0_SMRAMC)" )
            return ModuleResult.ERROR
        
        regval = chipsec.chipset.read_register( self.cs, 'PCI0.0.0_SMRAMC' )
        g_smrame = chipsec.chipset.get_register_field( self.cs, 'PCI0.0.0_SMRAMC', regval, 'G_SMRAME' )
        d_open   = chipsec.chipset.get_register_field( self.cs, 'PCI0.0.0_SMRAMC', regval, 'D_OPEN' )
        d_lock   = chipsec.chipset.get_register_field( self.cs, 'PCI0.0.0_SMRAMC', regval, 'D_LCK' )
      
        chipsec.chipset.print_register( self.cs, 'PCI0.0.0_SMRAMC', regval )

        res = ModuleResult.ERROR
        if 1 == g_smrame:
            self.logger.log( "[*] Compatible SMRAM is enabled" )
            # When D_LCK is set HW clears D_OPEN so generally no need to check for D_OPEN but doesn't hurt double checking
            if 1 == d_lock and 0 == d_open:
                res = ModuleResult.PASSED
                self.logger.log_passed_check( "Compatible SMRAM is locked down" )
            else:
                res = ModuleResult.FAILED
                self.logger.log_failed_check( "Compatible SMRAM is not properly locked. Expected ( D_LCK = 1, D_OPEN = 0 )" )
        else:
            res = ModuleResult.SKIPPED
            self.logger.log( "[*] Compatible SMRAM is not enabled. Skipping.." )

        return res


    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        return self.check_SMRAMC()
