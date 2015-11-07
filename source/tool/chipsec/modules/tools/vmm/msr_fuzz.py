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
Simple CPU Module Specific Register (MSR) VMM emulation fuzzer

 Usage:
   chipsec_main.py -i -m tools.vmm.msr_fuzz [-a random] -l msr_fuzz.log
"""

import random

from chipsec.module_common import *

#logger.VERBOSE = True

_MODULE_NAME = 'msr_fuzz'

# Number of iterations to fuzz randomly
global _NO_ITERATIONS_TO_FUZZ
_NO_ITERATIONS_TO_FUZZ = 100000

# Read MSR?
_READ_MSR = False

# Flush log file before each MSR
_FLUSH_LOG_EACH_MSR = False

# Control values to be written to each MSR
_FUZZ_VALUE_0_all1s = True
_FUZZ_VALUE_5A      = False
_FUZZ_VALUE_RND     = True

# Exclude MSRs which cause VM hang/crash
_EXCLUDE_MSR = []


class msr_fuzz (BaseModule):

    def fuzz_MSRs( self, msr_addr_start, random_order=False ):
        msr_addr_range = 0x10000
        msr_addr_end   = msr_addr_start + msr_addr_range
        self.logger.log( "[*] Fuzzing MSRs in range 0x%08X:0x%08X.." % (msr_addr_start,msr_addr_end) )
        it = 0
        if random_order: it_max = _NO_ITERATIONS_TO_FUZZ
        else:            it_max = msr_addr_range
        while it < it_max:
            if random_order: msr_addr = random.randint( msr_addr_start, msr_addr_end )
            else:            msr_addr = msr_addr_start + it
            if _FLUSH_LOG_EACH_MSR: self.logger.flush()
            if msr_addr not in _EXCLUDE_MSR:
                if _READ_MSR:
                    self.logger.log( "[*] rdmsr 0x%08X" % msr_addr )
                    try: (eax, edx) = self.cs.msr.read_msr( 0, msr_addr )
                    except: pass
                self.logger.log( "[*] wrmsr 0x%08X" % msr_addr )
                if _FUZZ_VALUE_0_all1s:
                    #self.logger.log( "    0" )
                    try: self.cs.msr.write_msr( 0, msr_addr, 0, 0 )
                    except: pass
                    #self.logger.log( "    0xFFFFFFFFFFFFFFFF" )
                    try: self.cs.msr.write_msr( 0, msr_addr, 0xFFFFFFFF, 0xFFFFFFFF )
                    except: pass
                if _FUZZ_VALUE_5A:
                    #self.logger.log( "    0x5A5A5A5A5A5A5A5A" )
                    try: self.cs.msr.write_msr( 0, msr_addr, 0x5A5A5A5A, 0x5A5A5A5A )
                    except: pass
                if _FUZZ_VALUE_RND:
                    val_hi = random.randint( 0, 0xFFFFFFFF )
                    val_lo = random.randint( 0, 0xFFFFFFFF )
                    #self.logger.log( "    0x%08X%08X" % (val_hi,val_lo) )
                    try: self.cs.msr.write_msr( 0, msr_addr, val_hi, val_lo )
                    except: pass
            it += 1
        return True


    def run( self, module_argv ):

        self.logger.start_test( "Fuzzing CPU Model Specific Registers (MSR)" )

        _random_order = False
        if len(module_argv) > 0 and 'random' == module_argv[0]:
            _random_order = True

        global _NO_ITERATIONS_TO_FUZZ
        _NO_ITERATIONS_TO_FUZZ = 100000

        self.logger.log( "[*] Configuration:" )
        self.logger.log( "    Mode: %s" % ('random' if _random_order else 'sequential') )
        if _random_order: self.logger.log( "    Number of iterations: %d" % _NO_ITERATIONS_TO_FUZZ )

        self.logger.log( "\n[*] Fuzzing Low MSR range.." )
        self.fuzz_MSRs( 0x0, _random_order )
        self.logger.log( "\n[*] Fuzzing High MSR range.." )
        self.fuzz_MSRs( 0xC0000000, _random_order )
        self.logger.log( "\n[*] Fuzzing VMM synthetic MSR range.." )
        self.fuzz_MSRs( 0x40000000, _random_order )
