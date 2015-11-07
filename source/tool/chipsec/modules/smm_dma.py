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
Just like SMRAM needs to be protected from software executing on the CPU, it also needs to be protected from devices that have direct access to DRAM (DMA). Protection from DMA is configured through proper programming of SMRAM memory range. If BIOS does not correctly configure and lock the configuration, then malware could reprogram configuration and open SMRAM area to DMA access, allowing manipulation of memory that should have been protected.

DMA attacks were discussed in `Programmed I/O accesses: a threat to Virtual Machine Monitors? <http://www.ssi.gouv.fr/archive/fr/sciences/fichiers/lti/pacsec2007-duflot-papier.pdf>`_ and `System Management Mode Design and Security Issues <http://www.ssi.gouv.fr/uploads/IMG/pdf/IT_Defense_2010_final.pdf>`_. This is also discussed in `Summary of Attack against BIOS and Secure Boot <https://www.defcon.org/images/defcon-22/dc-22-presentations/Bulygin-Bazhaniul-Furtak-Loucaides/DEFCON-22-Bulygin-Bazhaniul-Furtak-Loucaides-Summary-of-attacks-against-BIOS-UPDATED.pdf>`_ .

This module examines the configuration and locking of SMRAM range configuration protecting from DMA attacks. If it fails, then DMA protection may not be securely configured to protect SMRAM.
"""

from chipsec.module_common import *
import chipsec.chipset

_MODULE_NAME = 'smm_dma'

TAGS = [MTAG_SMM,MTAG_HWCONFIG]


_TSEG_MASK  = 0xFFF00000

class smm_dma(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        if self.cs.is_atom(): return False
        if self.cs.is_server(): return False
        else: return True

    def check_tseg_locks(self):
        tseg_base_lock = chipsec.chipset.get_control(self.cs, 'TSEGBaseLock')
        tseg_limit_lock = chipsec.chipset.get_control(self.cs, 'TSEGLimitLock')
        
        if tseg_base_lock and tseg_limit_lock:
            self.logger.log_good( "TSEG range is locked" )
            return ModuleResult.PASSED
        else:
            self.logger.log_bad( "TSEG range is not locked" )
            return ModuleResult.FAILED
        
    def check_tseg_config(self):
        res = ModuleResult.FAILED
        (tseg_base,  tseg_limit,  tseg_size ) = self.cs.cpu.get_TSEG()
        (smram_base, smram_limit, smram_size) = self.cs.cpu.get_SMRR_SMRAM()
        self.logger.log("[*] TSEG      : 0x%016X - 0x%016X (size = 0x%08X)"   % (tseg_base,  tseg_limit,  tseg_size ))      
        self.logger.log("[*] SMRR range: 0x%016X - 0x%016X (size = 0x%08X)\n" % (smram_base, smram_limit, smram_size))
        
        self.logger.log( "[*] checking TSEG range configuration.." )
        if (0 == smram_base) and (0 == smram_limit):
            res = ModuleResult.WARNING
            self.logger.log_warn_check( "TSEG is properly configured but can't determine if it covers entire SMRAM" )
            
        else:            
            if (tseg_base <= smram_base) and (smram_limit <= tseg_limit):
            #if (tseg_base == smram_base) and (tseg_size == smram_size):
                self.logger.log_good( "TSEG range covers entire SMRAM" )
                if self.check_tseg_locks() == ModuleResult.PASSED:                    
                    res = ModuleResult.PASSED
                    self.logger.log_passed_check( "TSEG is properly configured. SMRAM is protected from DMA attacks" )
                else:
                    self.logger.log_failed_check( "TSEG is properly configured, but the configuration is not locked." )
            else:
                self.logger.log_bad( "TSEG range doesn't cover entire SMRAM" )
                self.logger.log_failed_check( "TSEG is not properly configured. Portions of SMRAM may be vulnerable to DMA attacks" )

        return res

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        self.logger.start_test( "SMM TSEG Range Configuration Check" )
        self.res = self.check_tseg_config()
        return self.res
        