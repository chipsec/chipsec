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
# __chipsec/modules/common/smm.py__ - common checks for protection of compatible System Management Mode (SMM) memory (SMRAM)
#
from collections import namedtuple
from chipsec.module_common import MTAG_BIOS,MTAG_SMM, BaseModule, ModuleResult
TAGS = [MTAG_BIOS,MTAG_SMM]
#from chipsec.chipset import Cfg

class smm(BaseModule):
    
    def __init__(self):
        BaseModule.__init__(self)
        
    # PCI Dev0 SMRAMC register
    class SMRAMC( namedtuple('SMRAMC_REG', 'PCI_SMRAMC_REG_OFF value D_OPEN D_CLS D_LCK G_SMRAME C_BASE_SEG') ):
        __slots__ = ()
        def __str__(self):
            return """[*] Compatible SMRAM Control (00:00.0 + 0x%X) = 0x%02X
    [06]    D_OPEN     = %u (SMRAM Open)
    [05]    D_CLS      = %u (SMRAM Closed)
    [04]    D_LCK      = %u (SMRAM Locked)
    [03]    G_SMRAME   = %u (SMRAM Enabled)
    [02:00] C_BASE_SEG = %X (SMRAM Base Segment = 010b)
    """ % ( self.PCI_SMRAMC_REG_OFF, self.value, self.D_OPEN, self.D_CLS, self.D_LCK, self.G_SMRAME, self.C_BASE_SEG )         
    
    
    def check_SMRAMC(self):
        self.logger.start_test( "Compatible SMM memory (SMRAM) Protection" )
    
        regval = self.cs.pci.read_byte( 0, 0, 0, self.cs.Cfg.PCI_SMRAMC_REG_OFF )
        SMRAMRegister = smm.SMRAMC(self.cs.Cfg.PCI_SMRAMC_REG_OFF, regval, (regval>>6)&0x1, (regval>>5)&0x1, (regval>>4)&0x3, (regval>>3)&0x1, regval&0x7 )
        self.logger.log( SMRAMRegister )
    
        res = ModuleResult.ERROR
        if 1 == SMRAMRegister.G_SMRAME:
            self.logger.log( "[*] Compatible SMRAM is enabled" )
            # When D_LCK is set HW clears D_OPEN so generally no need to check for D_OPEN but doesn't hurt double checking
            if 1 == SMRAMRegister.D_LCK and 0 == SMRAMRegister.D_OPEN:
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
