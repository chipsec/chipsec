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
`Setup for Failure: Defeating SecureBoot <http://syscan.org/index.php/download/get/6e597f6067493dd581eed737146f3afb/SyScan2014_CoreyKallenberg_SetupforFailureDefeatingSecureBoot.zip>`_ by Corey Kallenberg, Xeno Kovah, John Butterworth, Sam Cornwell

Checks for SMI events configuration
"""

from chipsec.module_common import *
from chipsec.hal.iobar import * 


TAGS = [chipsec.module_common.MTAG_BIOS]

class bios_smi(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.iobar = iobar( self.cs )

    def is_supported(self):
        return (self.cs.get_chipset_id() not in chipsec.chipset.CHIPSET_FAMILY_ATOM)

    def check_SMI_locks(self):

        self.logger.start_test( "SMI Events Configuration" )
        
        if not chipsec.chipset.is_register_defined( self.cs, 'TCO1_CNT' ) or \
           not chipsec.chipset.is_register_defined( self.cs, 'GEN_PMCON_1' ) or \
           not chipsec.chipset.is_register_defined( self.cs, 'SMI_EN' ):
            self.logger.error( "Couldn't find definition of required configuration registers" )
            return ModuleResult.ERROR
        
        #
        # Checking SMM_BWP first in BIOS control to warn if SMM write-protection of the BIOS is not enabled
        #
        bc_reg = chipsec.chipset.read_register( self.cs, 'BC' )
        chipsec.chipset.print_register( self.cs, 'BC', bc_reg )
        smm_bwp = chipsec.chipset.get_register_field( self.cs, 'BC', bc_reg, 'SMM_BWP' )
        if 0 == smm_bwp: self.logger.log_bad( "SMM BIOS region write protection has not been enabled (SMM_BWP is not used)\n" )
        else:            self.logger.log_good( "SMM BIOS region write protection is enabled (SMM_BWP is used)\n" )

        ok = True

        #
        # Checking if global SMI and TCO SMI are enabled (GBL_SMI_EN and TCO_EN bits in SMI_EN register)
        #
        self.logger.log( "[*] Checking SMI enables.." )
        smi_en_reg = chipsec.chipset.read_register( self.cs, 'SMI_EN' )
        #chipsec.chipset.print_register( self.cs, 'SMI_EN', smi_en_reg )
        tco_en     = chipsec.chipset.get_register_field( self.cs, 'SMI_EN', smi_en_reg, 'TCO_EN' )
        gbl_smi_en = chipsec.chipset.get_register_field( self.cs, 'SMI_EN', smi_en_reg, 'GBL_SMI_EN' )
        self.logger.log( "    Global SMI enable: %d" % gbl_smi_en )
        self.logger.log( "    TCO SMI enable   : %d" % tco_en )

        if gbl_smi_en != 1:
            ok = False
            self.logger.log_bad( "Global SMI is not enabled" )
        elif tco_en != 1:
            self.logger.warn( "TCO SMI is not enabled. BIOS may not be using it" )
        else: self.logger.log_good( "All required SMI events are enabled" )
        self.logger.log('')

        #
        # Checking TCO_LOCK
        #
        self.logger.log( "[*] Checking SMI configuration locks.." )
        tco1_cnt_reg = chipsec.chipset.read_register( self.cs, 'TCO1_CNT')
        chipsec.chipset.print_register( self.cs, 'TCO1_CNT', tco1_cnt_reg )
        tco_lock = chipsec.chipset.get_register_field( self.cs, 'TCO1_CNT', tco1_cnt_reg, 'TCO_LOCK' )

        if tco_lock != 1:
            ok = False
            self.logger.log_bad( "TCO SMI event configuration is not locked. TCO SMI events can be disabled" )
        else: self.logger.log_good( "TCO SMI configuration is locked" )
        self.logger.log('')

        #
        # Checking SMI_LOCK
        #
        gen_pmcon_1_reg = chipsec.chipset.read_register( self.cs, 'GEN_PMCON_1')
        chipsec.chipset.print_register( self.cs, 'GEN_PMCON_1', gen_pmcon_1_reg )
        smi_lock = chipsec.chipset.get_register_field( self.cs, 'GEN_PMCON_1', gen_pmcon_1_reg, 'SMI_LOCK' )

        if smi_lock != 1:
            ok = False
            self.logger.log_bad( "SMI events global configuration is not locked. SMI events can be disabled" )
        else: self.logger.log_good( "SMI events global configuration is locked" )
        self.logger.log('')

        if ok:
            res = ModuleResult.PASSED
            self.logger.log_passed_check( "All required SMI sources seem to be enabled and locked" )
        else:
            if 1 == smm_bwp:
                res = ModuleResult.WARNING
                self.logger.log_warn_check( "Not all required SMI sources are enabled and locked, but SPI flash writes are still restricted to SMM" )
            else:
                res = ModuleResult.FAILED
                self.logger.log_failed_check( "Not all required SMI sources are enabled and locked" )
        return res



    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        return self.check_SMI_locks()
