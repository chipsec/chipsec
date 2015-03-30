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
# __chipsec/modules/common/bios_ts.py__ -checks for BIOS Top Swap Mode
#

from chipsec.module_common import *
TAGS = [chipsec.module_common.MTAG_BIOS]

class bios_ts(chipsec.module_common.BaseModule):
    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        if not chipsec.chipset.is_register_defined( self.cs, 'GCS' ):
            self.logger.error( "Couldn't find definition of required configuration registers (GCS)... skipping" )
            return False
        if not chipsec.chipset.register_has_field( self.cs, 'GCS', 'BILD'):
            self.logger.error( "Couldn't locate 'BIOS Interface Lock Down' bit in the configuration for the BUC register... skipping" )
            return False
        return True

    def check_top_swap_mode(self):

        self.logger.start_test( "BIOS Interface Lock and Top Swap Mode" )

        if not chipsec.chipset.is_register_defined( self.cs, 'BC'):
            self.logger.error("Couldn't find definition of required configuration registers (BC)")
        else:
            bc_reg = chipsec.chipset.read_register(self.cs, 'BC')
            chipsec.chipset.print_register( self.cs, 'BC', bc_reg )
               
        if not chipsec.chipset.register_has_field( self.cs, 'BC', 'TSS'):
            self.logger.error( "Couldn't locate 'Top Swap' bit in the configuration for the BC register" )
        else:
            tss  = chipsec.chipset.get_register_field( self.cs, 'BC', bc_reg, 'TSS' )
            self.logger.log( "[*] BIOS Top Swap mode is %s" % ('enabled' if (1==tss) else 'disabled') )

        if not chipsec.chipset.is_register_defined( self.cs, 'BUC' ):
            self.logger.error( "Couldn't find definition of required configuration registers (BUC)" )
        else: 
            buc_reg = chipsec.chipset.read_register( self.cs, 'BUC' )
            chipsec.chipset.print_register( self.cs, 'BUC', buc_reg )
            if not chipsec.chipset.register_has_field( self.cs, 'BUC', 'TS'):
                self.logger.error( "Couldn't locate 'Top Swap' bit in the configuration for the BUC register" )
            else:
                ts  = chipsec.chipset.get_register_field( self.cs, 'BUC', buc_reg, 'TS' )
                self.logger.log( "[*] RTC version of TS = %x" % ts )

        if not chipsec.chipset.is_register_defined( self.cs, 'GCS' ):
            self.logger.error( "Couldn't find definition of required configuration registers (GCS)" )
            return ModuleResult.ERROR
        gcs_reg = chipsec.chipset.read_register( self.cs, 'GCS' )
        chipsec.chipset.print_register( self.cs, 'GCS', gcs_reg )
        if not chipsec.chipset.register_has_field( self.cs, 'GCS', 'BILD' ):
            self.logger.error( "Couldn't locate 'BIOS Interface Lock-Down' bit in the configuration for the GCS register" )
            return ModuleResult.ERROR
        bild = chipsec.chipset.get_register_field( self.cs, 'GCS', gcs_reg, 'BILD' )

        self.logger.log( '' )
        if 0 == bild:
            self.logger.log_failed_check( "BIOS Interface is not locked (including Top Swap Mode)" )
            return ModuleResult.FAILED
        else:
            self.logger.log_passed_check( "BIOS Interface is locked (including Top Swap Mode)" )
            return ModuleResult.PASSED


    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run(self, module_argv ):
        return self.check_top_swap_mode()
