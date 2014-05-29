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
# __chipsec/modules/common/bios_ts.py__ -checks for BIOS Top Swap Mode
#

import chipsec.module_common 
TAGS = [chipsec.module_common.MTAG_BIOS]

import chipsec.hal.mmio as mmio


class bios_ts(chipsec.module_common.BaseModule):
    def __init__(self):
        chipsec.module_common.BaseModule.__init__(self)
        
    def get_RCBA_general_registers_base(self):
        rcba_general_base = mmio.get_MMIO_base_address( self.cs, mmio.MMIO_BAR_LPCRCBA ) + self.cs.Cfg.RCBA_GENERAL_CONFIG_OFFSET
        self.logger.log( "[*] RCBA General Config base: 0x%08X" % rcba_general_base )
        return rcba_general_base
    
    def check_top_swap_mode(self):
        self.logger.start_test( "BIOS Interface Lock and Top Swap Mode" )
    
        rcba_general_base = self.get_RCBA_general_registers_base()
        gcs_reg_value = self.cs.mem.read_physical_mem_dword( rcba_general_base + self.cs.Cfg.RCBA_GC_GCS_REG_OFFSET )
        self.logger.log( "[*] GCS (General Control and Status) register = 0x%08X" % gcs_reg_value )
        self.logger.log( "    [10] BBS  (BIOS Boot Straps)         = 0x%X " % ((gcs_reg_value & self.cs.Cfg.RCBA_GC_GCS_REG_BBS_MASK)>>10) )
        self.logger.log( "    [00] BILD (BIOS Interface Lock-Down) = %u" % (gcs_reg_value & self.cs.Cfg.RCBA_GC_GCS_REG_BILD_MASK) )
    
        buc_reg_value = self.cs.mem.read_physical_mem_dword( rcba_general_base + self.cs.Cfg.RCBA_GC_BUC_REG_OFFSET )
        self.logger.log( "[*] BUC (Backed Up Control) register = 0x%08X" % buc_reg_value )
        self.logger.log( "    [00] TS (Top Swap) = %u" % (buc_reg_value & self.cs.Cfg.RCBA_GC_BUC_REG_TS_MASK) )
    
        reg_value = self.cs.pci.read_byte( 0, 31, 0, self.cs.Cfg.LPC_BC_REG_OFF )
        BcRegister = self.cs.Cfg.LPC_BC_REG( reg_value, (reg_value>>5)&0x1, (reg_value>>4)&0x1, (reg_value>>2)&0x3, (reg_value>>1)&0x1, reg_value&0x1 )
        #self.logger.log( BcRegister )
        self.logger.log( "[*] BC (BIOS Control) register = 0x%02X" % reg_value )
        self.logger.log( "    [04] TSS (Top Swap Status) = %u" % BcRegister.TSS )
        self.logger.log( "[*] BIOS Top Swap mode is %s" % ('enabled' if BcRegister.TSS else 'disabled') )
      
        self.logger.log( '' )
        if 0 == (gcs_reg_value & self.cs.Cfg.RCBA_GC_GCS_REG_BILD_MASK):
            self.logger.log_failed_check( "BIOS Interface is not locked (including Top Swap Mode)" )
            return False
        else:
            self.logger.log_passed_check( "BIOS Interface is locked (including Top Swap Mode)" )
            return True
    
    
    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run(self, module_argv ):
        return self.check_top_swap_mode()
