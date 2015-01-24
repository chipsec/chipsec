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
# __chipsec/modules/smm_dma.py__ - check SMM memory (SMRAM) is properly configured to protect from DMA attacks
#

from chipsec.module_common import *
import chipsec.chipset

_MODULE_NAME = 'smm_dma'

TAGS = [MTAG_SMM,MTAG_HWCONFIG]


IA32_SMRR_BASE_MEMTYPE_MASK = 0x7
IA32_SMRR_BASE_BASE_MASK    = 0xFFFFF000

IA32_SMRR_MASK_VLD_MASK     = 0x800
IA32_SMRR_MASK_MASK_MASK    = 0xFFFFF000

ALIGNED_8MB   = 0x7FFFFF

_TSEG_MASK      = 0xFFFFF000

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

        tolud      = chipsec.chipset.read_register( self.cs, 'PCI0.0.0_TOLUD' )
        bgsm       = chipsec.chipset.read_register( self.cs, 'PCI0.0.0_BGSM' )
        tsegmb     = chipsec.chipset.read_register( self.cs, 'PCI0.0.0_TSEGMB' )
        smrr_base  = chipsec.chipset.read_register( self.cs, 'IA32_SMRR_PHYSBASE' )
        smrr_mask  = chipsec.chipset.read_register( self.cs, 'IA32_SMRR_PHYSMASK' )

        self.logger.log( "[*] Registers:" )
        self.logger.log( "[*]   TOLUD             : 0x%08X" % tolud )
        self.logger.log( "[*]   BGSM              : 0x%08X" % bgsm )
        self.logger.log( "[*]   TSEGMB            : 0x%08X" % tsegmb )
        self.logger.log( "[*]   IA32_SMRR_PHYSBASE: 0x%016X" % smrr_base )
        self.logger.log( "[*]   IA32_SMRR_PHYSMASK: 0x%016X\n" % smrr_mask )

        tolud_lock      = tolud  & 0x1
        bgsm_lock       = bgsm   & 0x1
        tsegmb_lock     = tsegmb & 0x1
        tolud  &= _TSEG_MASK
        bgsm   &= _TSEG_MASK
        tsegmb &= _TSEG_MASK
        tseg_size = bgsm - tsegmb
        tseg_limit = tsegmb + tseg_size - 1

        smrrbase = chipsec.chipset.get_register_field( self.cs, 'IA32_SMRR_PHYSBASE', smrr_base, 'PhysBase', True )
        smrrmask = chipsec.chipset.get_register_field( self.cs, 'IA32_SMRR_PHYSMASK', smrr_mask, 'PhysMask', True )
        # Actual SMRR Base = SMRR_BASE & SMRR_MASK
        smrrbase &= smrrmask
        smrrsize = ((~(smrrmask & IA32_SMRR_MASK_MASK_MASK))&0xFFFFFFFF) + 1
        smrrlimit = smrrbase + smrrsize - 1

        self.logger.log( "[*] Memory Map:" )
        self.logger.log( "[*]   Top Of Low Memory       : 0x%08X" % tolud )
        self.logger.log( "[*]   TSEG Range (TSEGMB-BGSM): [0x%08X-0x%08X]" % (tsegmb,tseg_limit) )
        self.logger.log( "[*]   SMRR Range              : [0x%08X-0x%08X]\n" % (smrrbase,smrrlimit) )

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
        ok = (0 == tsegmb & ALIGNED_8MB) #(0 == tsegmb & self.cs.Cfg.ALIGNED_8MB)
        smram_dma_ok = smram_dma_ok and ok
        if ok: self.logger.log_good( "  TSEGMB is 8MB aligned" )
        else:  self.logger.log_bad( "  TSEGMB is not 8MB aligned" )

        self.logger.log( "[*] checking TSEG covers entire SMRR range.." )
        ok = (tsegmb <= smrrbase) and (smrrlimit <= tseg_limit)
        smram_dma_ok = smram_dma_ok and ok
        if ok: self.logger.log_good( "  TSEG covers entire SMRAM" )
        else:  self.logger.log_bad( "  TSEG doesn't cover entire SMRAM" )

        self.logger.log('')
        if smram_dma_ok: self.logger.log_passed_check( "TSEG is properly configured. SMRAM is protected from DMA attacks" )
        else:            self.logger.log_failed_check( "TSEG is not properly configured. SMRAM is vulnerable to DMA attacks" )

        return smram_dma_ok

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        return self.check_tseg_config()
