#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2020, Intel Corporation
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
The module checks that SMI events configuration is locked down
- Global SMI Enable/SMI Lock
- TCO SMI Enable/TCO Lock

References:

`Setup for Failure: Defeating SecureBoot <http://syscan.org/index.php/download/get/6e597f6067493dd581eed737146f3afb/SyScan2014_CoreyKallenberg_SetupforFailureDefeatingSecureBoot.zip>`_ by Corey Kallenberg, Xeno Kovah, John Butterworth, Sam Cornwell

`Summary of Attacks Against BIOS and Secure Boot` (https://www.defcon.org/images/defcon-22/dc-22-presentations/Bulygin-Bazhaniul-Furtak-Loucaides/DEFCON-22-Bulygin-Bazhaniul-Furtak-Loucaides-Summary-of-attacks-against-BIOS-UPDATED.pdf)
"""

from chipsec.module_common import BaseModule, ModuleResult, MTAG_BIOS, MTAG_SMM

TAGS = [MTAG_BIOS,MTAG_SMM]

class bios_smi(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        return True

    def check_SMI_locks(self):

        self.logger.start_test( "SMI Events Configuration" )

        if not self.cs.is_control_defined( 'SmmBiosWriteProtection' ) or \
           not self.cs.is_control_defined( 'TCOSMIEnable' ) or \
           not self.cs.is_control_defined( 'GlobalSMIEnable' ) or \
           not self.cs.is_control_defined( 'TCOSMILock' ) or \
           not self.cs.is_control_defined( 'SMILock' ):
            self.logger.error( "Couldn't find definition of required configuration registers" )
            return ModuleResult.ERROR

        #
        # Checking SMM_BWP first in BIOS control to warn if SMM write-protection of the BIOS is not enabled
        #
        smm_bwp = self.cs.get_control( 'SmmBiosWriteProtection' )
        if 0 == smm_bwp: self.logger.log_bad( "SMM BIOS region write protection has not been enabled (SMM_BWP is not used)\n" )
        else:            self.logger.log_good( "SMM BIOS region write protection is enabled (SMM_BWP is used)\n" )

        ok = True

        #
        # Checking if global SMI and TCO SMI are enabled (GBL_SMI_EN and TCO_EN bits in SMI_EN register)
        #
        self.logger.log( "[*] Checking SMI enables.." )
        tco_en     = self.cs.get_control( 'TCOSMIEnable' )
        gbl_smi_en = self.cs.get_control( 'GlobalSMIEnable' )
        self.logger.log( "    Global SMI enable: {:d}".format(gbl_smi_en) )
        self.logger.log( "    TCO SMI enable   : {:d}".format(tco_en) )

        if gbl_smi_en != 1:
            ok = False
            self.logger.log_bad( "Global SMI is not enabled" )
        elif tco_en != 1:
            self.logger.warn( "TCO SMI is not enabled. BIOS may not be using it" )
        else: self.logger.log_good( "All required SMI events are enabled" )
        self.logger.log('')

        self.logger.log( "[*] Checking SMI configuration locks.." )

        #
        # Checking TCO_LOCK
        #
        tco_lock = self.cs.get_control( 'TCOSMILock')
        if tco_lock != 1:
            ok = False
            self.logger.log_bad( "TCO SMI event configuration is not locked. TCO SMI events can be disabled" )
        else: self.logger.log_good( "TCO SMI configuration is locked (TCO SMI Lock)" )

        #
        # Checking SMI_LOCK
        #
        smi_lock = self.cs.get_control( 'SMILock' )
        if smi_lock != 1:
            ok = False
            self.logger.log_bad( "SMI events global configuration is not locked. SMI events can be disabled" )
        else: self.logger.log_good( "SMI events global configuration is locked (SMI Lock)" )
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
