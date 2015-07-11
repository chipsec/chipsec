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


ALIGNED_8MB   = 0x7FFFFF

class smm_dma(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        if self.cs.get_chipset_id() in chipsec.chipset.CHIPSET_FAMILY_CORE:
            return True
        return False

    def check_tseg_config(self):
        self.logger.start_test( "SMRAM DMA Protection" )

        if not chipsec.chipset.is_register_defined( self.cs, 'PCI0.0.0_TSEGMB' ) or \
           not chipsec.chipset.is_register_defined( self.cs, 'PCI0.0.0_BGSM' ):
            self.logger.error( "Couldn't find definition of required registers (TSEG, BGSM)" )
            return ModuleResult.ERROR

        tolud_reg  = chipsec.chipset.read_register( self.cs, 'PCI0.0.0_TOLUD' )
        bgsm_reg   = chipsec.chipset.read_register( self.cs, 'PCI0.0.0_BGSM' )
        tsegmb_reg = chipsec.chipset.read_register( self.cs, 'PCI0.0.0_TSEGMB' )
        smrr_base  = chipsec.chipset.read_register( self.cs, 'IA32_SMRR_PHYSBASE' )
        smrr_mask  = chipsec.chipset.read_register( self.cs, 'IA32_SMRR_PHYSMASK' )

        self.logger.log( "[*] Registers:" )
        chipsec.chipset.print_register( self.cs, 'PCI0.0.0_TOLUD', tolud_reg )
        chipsec.chipset.print_register( self.cs, 'PCI0.0.0_BGSM', bgsm_reg )
        chipsec.chipset.print_register( self.cs, 'PCI0.0.0_TSEGMB', tsegmb_reg )
        chipsec.chipset.print_register( self.cs, 'IA32_SMRR_PHYSBASE', smrr_base )
        chipsec.chipset.print_register( self.cs, 'IA32_SMRR_PHYSMASK', smrr_mask )
        #self.logger.log( "[*]   TOLUD             : 0x%08X" % tolud )
        #self.logger.log( "[*]   BGSM              : 0x%08X" % bgsm )
        #self.logger.log( "[*]   TSEGMB            : 0x%08X" % tsegmb )
        #self.logger.log( "[*]   IA32_SMRR_PHYSBASE: 0x%016X" % smrr_base )
        #self.logger.log( "[*]   IA32_SMRR_PHYSMASK: 0x%016X\n" % smrr_mask )

        tolud_lock  = chipsec.chipset.get_register_field( self.cs, 'PCI0.0.0_TOLUD'    , tolud_reg , 'LOCK' )
        bgsm_lock   = chipsec.chipset.get_register_field( self.cs, 'PCI0.0.0_BGSM'     , bgsm_reg  , 'LOCK' )
        tsegmb_lock = chipsec.chipset.get_register_field( self.cs, 'PCI0.0.0_TSEGMB'   , tsegmb_reg, 'LOCK' )
        tolud       = chipsec.chipset.get_register_field( self.cs, 'PCI0.0.0_TOLUD'    , tolud_reg , 'TOLUD'   , True )
        bgsm        = chipsec.chipset.get_register_field( self.cs, 'PCI0.0.0_BGSM'     , bgsm_reg  , 'BGSM'    , True )
        tsegmb      = chipsec.chipset.get_register_field( self.cs, 'PCI0.0.0_TSEGMB'   , tsegmb_reg, 'TSEGMB'  , True )
        smrrbase    = chipsec.chipset.get_register_field( self.cs, 'IA32_SMRR_PHYSBASE', smrr_base , 'PhysBase', True )
        smrrmask    = chipsec.chipset.get_register_field( self.cs, 'IA32_SMRR_PHYSMASK', smrr_mask , 'PhysMask', True )

        tseg_size = bgsm - tsegmb
        tseg_limit = tsegmb + tseg_size - 1

        # Actual SMRR Base = SMRR_BASE & SMRR_MASK
        smrrbase &= smrrmask
        smrrsize = ((~smrrmask)&0xFFFFFFFF) + 1
        smrrlimit = smrrbase + smrrsize - 1

        self.logger.log( '' )
        self.logger.log( "[*] Memory Map:" )
        self.logger.log( "[*]   Top Of Low Memory             : 0x%08X" % tolud )
        self.logger.log( "[*]   TSEG Range (TSEGMB-BGSM)      : [0x%08X-0x%08X]" % (tsegmb,tseg_limit) )
        self.logger.log( "[*]   SMRR Range (size = 0x%08X): [0x%08X-0x%08X]\n" % (smrrsize,smrrbase,smrrlimit) )

        smram_dma_ok = True

        self.logger.log( "[*] checking locks.." )
        ok = (0 != tsegmb_lock)
        smram_dma_ok = smram_dma_ok and ok
        if ok: self.logger.log_good( "  TSEGMB is locked" )
        else:  self.logger.log_bad( "  TSEGMB is not locked" )

        ok = (0 != bgsm_lock)
        smram_dma_ok = smram_dma_ok and ok
        if ok: self.logger.log_good( "  BGSM is locked" )
        else:  self.logger.log_bad( "  BGSM is not locked" )

        self.logger.log( "[*] checking TSEG alignment.." )
        ok = (0 == tsegmb & ALIGNED_8MB)
        smram_dma_ok = smram_dma_ok and ok
        if ok: self.logger.log_good( "  TSEGMB is 8MB aligned" )
        else:  self.logger.log_bad( "  TSEGMB is not 8MB aligned" )

        self.logger.log( "[*] checking TSEG covers entire SMRR range.." )
        is_smrr_setup = (0 != smrrmask)
        if is_smrr_setup:
            ok = (tsegmb <= smrrbase) and (smrrlimit <= tseg_limit)
            smram_dma_ok = smram_dma_ok and ok
            if ok: self.logger.log_good( "  TSEG covers entire SMRAM" )
            else:  self.logger.log_bad( "  TSEG doesn't cover entire SMRAM" )
        else:
            self.logger.log_bad( "  SMRR range is not setup" )

        self.logger.log('')
        if smram_dma_ok:
            if is_smrr_setup:
                res = ModuleResult.PASSED
                self.logger.log_passed_check( "TSEG is properly configured. SMRAM is protected from DMA attacks" )
            else:
                res = ModuleResult.WARNING
                self.logger.log_warn_check( "TSEG is properly configured but can't determine if it covers entire SMRAM" )
        else:
            res = ModuleResult.FAILED
            self.logger.log_failed_check( "TSEG is not properly configured. SMRAM is vulnerable to DMA attacks" )

        return res

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        return self.check_tseg_config()
