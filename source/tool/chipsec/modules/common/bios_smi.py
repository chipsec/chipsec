#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2014, Intel Corporation
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
# __chipsec/modules/common/bios_smi.py__ - checks for SMI events configuration
#

## \file
# checks for SMI locks
#
# __chipsec/modules/common/bios_smi.py__ - checks for SMI events configuration

from chipsec.module_common import *
from chipsec.hal.iobar import iobar
from chipsec.hal.spi   import SPI

TAGS = [MTAG_BIOS]

class bios_smi(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.iobar = iobar( self.cs )
        self.spi   = SPI( self.cs )
    
    def is_supported(self):
        return (self.cs.get_chipset_id() not in chipsec.chipset.CHIPSET_FAMILY_ATOM)

    def get_PMBASE(self):
        if self.iobar.is_IO_BAR_defined( 'PMBASE' ):
            (io_base,io_size) = self.iobar.get_IO_BAR_base_address( 'PMBASE' )
            return io_base
        else:
            return (self.cs.pci.read_dword( 0, 31, 0, self.cs.Cfg.CFG_REG_PCH_LPC_PMBASE ) & self.cs.Cfg.CFG_REG_PCH_LPC_PMBASE_MASK)
    
    def get_TCOBASE(self):
        return (self.get_PMBASE() + self.cs.Cfg.TCOBASE_ABASE_OFFSET)
    
    def check_SMI_locks(self):

        self.logger.start_test( "SMI Events Configuration" )
    
        #
        # First check SMM_BWP in BIOS control to warn if SMM write-protection of the BIOS is not enabled
        #
        (BcRegister, reg_value) = self.spi.get_BIOS_Control()
        #self.logger.log( BcRegister )
        if 0 == BcRegister.SMM_BWP: self.logger.log_bad( "SMM BIOS region write protection has not been enabled (SMM_BWP is not used)\n" )

        ok = True

        #
        # Check if global SMI is enabled and TCO SMI is enabled (GBL_SMI_EN and TCO_EN in PMBASE[SMI_EN])
        #
        pmbase = self.get_PMBASE()
        self.logger.log("[*] PMBASE (ACPI I/O Base) = 0x%04X" % pmbase )

        smi_en = self.cs.io.read_port_dword( pmbase + self.cs.Cfg.PMBASE_SMI_EN )
        self.logger.log("[*] SMI_EN (SMI Control and Enable) register [I/O port 0x%X] = 0x%08X" % (pmbase + self.cs.Cfg.PMBASE_SMI_EN,smi_en) )
        self.logger.log("    [13] TCO_EN (TCO Enable)            = %u" % ((smi_en & (1<<13)) >> 13) )
        self.logger.log("    [00] GBL_SMI_EN (Global SMI Enable) = %u" % (smi_en & 0x1) )

        if (smi_en & 0x1) != 1:
            ok = False
            self.logger.log_bad( "Global SMI is not enabled" )
        elif ((smi_en & (1<<13)) >> 13) != 1:
            self.logger.warn( "TCO SMI is not enabled. BIOS may not be using it" )
        else: self.logger.log_good( "All required SMI events are enabled" )
    
        #
        # TCO_LOCK TCOBASE I/O register
        #
        tcobase = pmbase + self.cs.Cfg.TCOBASE_ABASE_OFFSET
        self.logger.log("[*] TCOBASE (TCO I/O Base) = 0x%04X" % tcobase )

        tco1_cnt = self.cs.io.read_port_word( tcobase + 0x8 ) # TCO1_CNT (TCOBASE + 0x8 = (ACPIBASE + 0x60) + 0x8)
        self.logger.log("[*] TCO1_CNT (TCO1 Control) register [I/O port 0x%X] = 0x%04X" % (tcobase + 0x8, tco1_cnt) )
        self.logger.log("    [12] TCO_LOCK = %u" % ((tco1_cnt & (1<<12)) >> 12) )

        if ((tco1_cnt & (1<<12)) >> 12) != 1:
            ok = False
            self.logger.log_bad( "TCO SMI event configuration is not locked. TCO SMI events can be disabled" )
        else: self.logger.log_good( "TCO SMI configuration is locked" )
    
        #
        # SMI_LOCK 0:31:0 PCIe CFG register
        #
        gen_pmcon_1 = self.cs.pci.read_word( 0, 31, 0, self.cs.Cfg.GEN_PMCON ) # BDF 0:31:0 offset 0xA0 (GEN_PMCON_1), SMI_LOCK is bit 0
        self.logger.log("[*] GEN_PMCON_1 (General PM Config 1) register [BDF 0:31:0 + 0x%X] = 0x%04X" % (self.cs.Cfg.GEN_PMCON, gen_pmcon_1) )
        self.logger.log("    [04] SMI_LOCK = %u" % ((gen_pmcon_1 & (1<<4)) >> 4) )

        if ((gen_pmcon_1 & (1<<4)) >> 4) != 1:
            ok = False
            self.logger.log_bad( "SMI events global configuration is not locked. SMI events can be disabled" )
        else: self.logger.log_good( "SMI events global configuration is locked" )
    
        if ok:
            res = ModuleResult.PASSED
            self.logger.log_passed_check( "All required SMI sources seem to be enabled and locked!" )
        else:
            if BcRegister.SMM_BWP == 1:
                res = ModuleResult.WARNING
                self.logger.log_warn_check( "Not all required SMI sources are enabled and locked, but SPI flash writes are still restricted to SMM." )
            else:
                res = ModuleResult.FAILED
                self.logger.log_failed_check( "Not all required SMI sources are enabled and locked!" )
        return res
    
    
    
    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        return self.check_SMI_locks()
