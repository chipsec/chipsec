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
# __chipsec/modules/common/smrr.py__ - checks for SMRR secure configuration to protect from SMRAM cache attack
#


from chipsec.module_common import *
TAGS = [MTAG_BIOS,MTAG_SMM]

from chipsec.hal.msr import *


# ############################################################
# SPECIFY PLATFORMS THIS MODULE IS APPLICABLE TO
# ############################################################


class smrr(BaseModule):
    
    def __init__(self):
        BaseModule.__init__(self)

    #
    # Check that SMRR are supported by CPU in IA32_MTRRCAP_MSR[SMRR]
    #
    def check_SMRR_supported(self):
        (eax, edx) = self.cs.msr.read_msr( 0, self.cs.Cfg.IA32_MTRRCAP_MSR )
        if self.logger.VERBOSE:
            self.logger.log( "[*] IA32_MTRRCAP_MSR = 0x%08X%08X" % (edx, eax) )
            self.logger.log( "    SMRR = %u" % ((eax&self.cs.Cfg.IA32_MTRRCAP_SMRR_MASK)>>11) )
        return (eax & self.cs.Cfg.IA32_MTRRCAP_SMRR_MASK)
    
    def check_SMRR(self):
        self.logger.start_test( "CPU SMM Cache Poisoning / SMM Range Registers (SMRR)" )
        if self.check_SMRR_supported():
            self.logger.log_good( "OK. SMRR are supported in IA32_MTRRCAP_MSR" )
        else:
            self.logger.log_important( "CPU does not support SMRR protection of SMRAM" )
            self.logger.log_skipped_check("CPU does not support SMRR protection of SMRAM")
            return ModuleResult.SKIPPED
    
        #
        # SMRR are supported
        # 
        smrr_ok = True
    
        #
        # 2. Check SMRR_BASE is programmed correctly (on CPU0)
        #
        self.logger.log( '' )
        self.logger.log( "[*] Checking SMRR Base programming.." )
        (eax, edx) = self.cs.msr.read_msr( 0, self.cs.Cfg.IA32_SMRR_BASE_MSR )
        msr_smrrbase = ((edx << 32) | eax)
        smrrbase_msr = eax
        smrrbase = smrrbase_msr & self.cs.Cfg.IA32_SMRR_BASE_BASE_MASK
        self.logger.log( "[*] IA32_SMRR_BASE_MSR = 0x%08X%08X" % (edx, eax) )
        self.logger.log( "    BASE    = 0x%08X" % smrrbase )
        self.logger.log( "    MEMTYPE = %X"     % (smrrbase_msr& self.cs.Cfg.IA32_SMRR_BASE_MEMTYPE_MASK) )
    
        if ( 0 != smrrbase ):
            if ( self.cs.Cfg.MTRR_MEMTYPE_WB == smrrbase_msr & self.cs.Cfg.IA32_SMRR_BASE_MEMTYPE_MASK ): self.logger.log_good( "SMRR Memtype is WB" )
            else: self.logger.log_important( "SMRR Memtype (= %X) is not WB", (smrrbase_msr & self.cs.Cfg.IA32_SMRR_BASE_MEMTYPE_MASK) )
        else:
            smrr_ok = False
            self.logger.log_bad( "SMRR Base is not programmed" )
    
        if smrr_ok: self.logger.log_good( "OK so far. SMRR Base is programmed" )
    
        #
        # 3. Check SMRR_MASK is programmed and SMRR are enabled (on CPU0)
        #
        self.logger.log( '' )
        self.logger.log( "[*] Checking SMRR Mask programming.." )
        (eax, edx) = self.cs.msr.read_msr( 0, self.cs.Cfg.IA32_SMRR_MASK_MSR )
        msr_smrrmask = ((edx << 32) | eax)
        smrrmask_msr = eax
        self.logger.log( "[*] IA32_SMRR_MASK_MSR = 0x%08X%08X" % (edx, eax) )
        self.logger.log( "    MASK    = 0x%08X" %  (smrrmask_msr & self.cs.Cfg.IA32_SMRR_MASK_MASK_MASK) )
        self.logger.log( "    VLD     = %u"     % ((smrrmask_msr & self.cs.Cfg.IA32_SMRR_MASK_VLD_MASK)>>11) )
    
        if not ( smrrmask_msr & self.cs.Cfg.IA32_SMRR_MASK_VLD_MASK and smrrmask_msr & self.cs.Cfg.IA32_SMRR_MASK_MASK_MASK ):
            smrr_ok = False
            self.logger.log_bad( "SMRR are not enabled in SMRR_MASK MSR" )
    
        if smrr_ok: self.logger.log_good( "OK so far. SMRR are enabled in SMRR_MASK MSR" )
    
        #
        # 4. Verify that SMRR_BASE/MASK MSRs have the same values on all logical CPUs
        #
        self.logger.log( '' )
        self.logger.log( "[*] Verifying that SMRR_BASE/MASK have the same values on all logical CPUs.." )
        for tid in range(self.cs.msr.get_cpu_thread_count()):
            (eax, edx) = self.cs.msr.read_msr( tid, self.cs.Cfg.IA32_SMRR_BASE_MSR )
            msr_base = ((edx << 32) | eax)
            (eax, edx) = self.cs.msr.read_msr( tid, self.cs.Cfg.IA32_SMRR_MASK_MSR )
            msr_mask = ((edx << 32) | eax)
            self.logger.log( "[CPU%d] SMRR_BASE = %016X, SMRR_MASK = %016X"% (tid, msr_base, msr_mask) )
            if (msr_base != msr_smrrbase) or (msr_mask != msr_smrrmask):
                smrr_ok = False
                self.logger.log_bad( "SMRR MSRs do not match on all CPUs" )
                break
    
        if smrr_ok: self.logger.log_good( "OK so far. SMRR MSRs match on all CPUs" )
    
        """
        Don't want invasive action in this test
        #
        # 5. Reading from & writing to SMRR_BASE physical address
        # writes should be dropped, reads should return all F's
        #
        self.logger.log( "[*] Trying to read/modify memory at SMRR_BASE address 0x%08X.." % smrrbase )
        smram_buf = self.cs.mem.read_physical_mem( smrrbase, 0x10 )
        #self.logger.log( "Contents at 0x%08X:\n%s" % (smrrbase, repr(smram_buf.raw)) )
        self.cs.mem.write_physical_mem_dword( smrrbase, 0x90909090 )
        if ( 0xFFFFFFFF == self.cs.mem.read_physical_mem_dword( smrrbase ) ):
            self.logger.log_good( "OK. Memory at SMRR_BASE contains all F's and is not modifiable" )
        else:
            smrr_ok = False
            self.logger.log_bad( "Contents of memory at SMRR_BASE are modifiable" )
        """
    
    
        self.logger.log( '' )
        if not smrr_ok: self.logger.log_failed_check( "SMRR protection against cache attack is not configured properly" )
        else:           self.logger.log_passed_check( "SMRR protection against cache attack seems properly configured" )
    
        return smrr_ok
    
    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
            return self.check_SMRR()
            
