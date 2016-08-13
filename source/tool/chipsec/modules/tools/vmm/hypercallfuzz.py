#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2016, Intel Corporation
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
Pretty simple VMM hypercall fuzzer

 Usage:
   ``chipsec_main.py -i -m tools.vmm.hypercallfuzz [ -a <mode>,<vector_reg>,<maxval>,<iterations> ] -l hypercallfuzz.log``
   ``  mode            hypercall fuzzing mode``
   ``    = exhaustive  fuzz all arguments exhaustively in range [0:<maxval>] (default)``
   ``    = random      send random values in all registers in range [0:<maxval>]``
   ``  vector_reg      hypercall vector register``
   ``  maxval          maximum value of each register``
   ``  iterations      number of iterations in random mode``
"""
import random
import time

from chipsec.module_common import *
import chipsec.hal.vmm

DEFAULT_VECTOR_MAXVAL     = 0xFF

DEFAULT_MAXVAL_EXHAUSTIVE = 0xFF
DEFAULT_MAXVAL_RANDOM     = 0xFFFFFFFF

DEFAULT_RANDOM_ITERATIONS = 0x7FFFFFFF

# Flush log file before each port
_FLUSH_LOG_EACH_ITER = False
_LOG_ALL_GPRS        = True

GPRS = { 'rax': 0, 'rbx': 0, 'rcx': 0, 'rdx': 0, 'rdi': 0, 'rsi': 0, 'r8' : 0, 'r9' : 0, 'r10': 0, 'r11': 0 }

class hypercallfuzz(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.vmm = chipsec.hal.vmm.VMM( self.cs )

        self.random_order = True
        self.gprs         = GPRS
        self.vector_reg   = None
        self.iterations   = DEFAULT_RANDOM_ITERATIONS
        self.maxval       = DEFAULT_MAXVAL_RANDOM

    def is_supported(self):
        return True


    def fuzz_generic_hypercalls( self ):

        _fmt = '%02X' if self.maxval <= 0xFF else ('%04X' if self.maxval <= 0xFFFF else ('%08X' if self.maxval <= 0xFFFFFFFF else '%016X'))
        _str = "%%d hcall rax=%s,rbx=%s,rcx=%s,rdx=%s,rdi=%s,rsi=%s,r8=%s,r9=%s,r10=%s,r11=%s" % (_fmt,_fmt,_fmt,_fmt,_fmt,_fmt,_fmt,_fmt,_fmt,_fmt)

        t = time.time()
        if self.random_order:

            self.logger.log( "[*] Fuzzing %d random hypercalls with random arguments..." % self.iterations )
            for it in xrange(self.iterations):
                rax = random.randint(0, self.gprs['rax'])
                rbx = random.randint(0, self.gprs['rbx'])
                rcx = random.randint(0, self.gprs['rcx'])
                rdx = random.randint(0, self.gprs['rdx'])
                rdi = random.randint(0, self.gprs['rdi'])
                rsi = random.randint(0, self.gprs['rsi'])
                r8  = random.randint(0, self.gprs['r8'])
                r9  = random.randint(0, self.gprs['r9'])
                r10 = random.randint(0, self.gprs['r10'])
                r11 = random.randint(0, self.gprs['r11'])
                if _LOG_ALL_GPRS: self.logger.log( _str % (it,rax,rbx,rcx,rdx,rdi,rsi,r8,r9,r10,r11) )
                else:             self.logger.log( "%d hcall" % it )
                if _FLUSH_LOG_EACH_ITER: self.logger.flush()
                try:
                    res = self.vmm.hypercall( rax, rbx, rcx, rdx, rdi, rsi, r8, r9, r10, r11 )
                except: pass

        else:

            it = 0
            self.logger.log( "[*] Fuzzing hypercalls with arguments exhaustively..." )
            for rax in xrange(self.gprs['rax']):
                for rbx in xrange(self.gprs['rbx']):
                    for rcx in xrange(self.gprs['rcx']):
                        for rdx in xrange(self.gprs['rdx']):
                            for rdi in xrange(self.gprs['rdi']):
                                for rsi in xrange(self.gprs['rsi']):
                                    for r8 in xrange(self.gprs['r8']):
                                        for r9 in xrange(self.gprs['r9']):
                                            for r10 in xrange(self.gprs['r10']):
                                                for r11 in xrange(self.gprs['r11']):
                                                    if _LOG_ALL_GPRS: self.logger.log( _str % (it,rax,rbx,rcx,rdx,rdi,rsi,r8,r9,r10,r11) )
                                                    else:             self.logger.log( "%d hcall" % it )
                                                    if _FLUSH_LOG_EACH_ITER: self.logger.flush()
                                                    try:
                                                        res = self.vmm.hypercall( rax, rbx, rcx, rdx, rdi, rsi, r8, r9, r10, r11 )
                                                        it += 1
                                                    except: pass

        self.logger.log( "[*] finished fuzzing: time elapsed %.3f" % (time.time()-t) )
        return ModuleResult.PASSED


    def usage( self ):
        self.logger.log( "Usage: chipsec_main -m tools.vmm.hypercallfuzz [ -a <mode>,<vector_reg>,<maxval>,<iterations> ]" )
        self.logger.log( "  mode            hypercall fuzzing mode" )
        self.logger.log( "    = exhaustive  fuzz all arguments exhaustively in range [0:<maxval>] (default)")
        self.logger.log( "    = random      send random values in all registers in range [0:<maxval>]" )
        self.logger.log( "  vector_reg      hypercall vector register" )
        self.logger.log( "  maxval          maximum value of each register" )
        self.logger.log( "  iterations      number of iterations in random mode (default = %d)" % DEFAULT_RANDOM_ITERATIONS )

    def run( self, module_argv ):

        self.logger.start_test( "Dumb VMM hypercall fuzzer" )
        self.usage()

        if len(module_argv) > 0: self.random_order = (module_argv[0].lower() == 'random')
        self.maxval = DEFAULT_MAXVAL_RANDOM if self.random_order else DEFAULT_MAXVAL_EXHAUSTIVE
        if len(module_argv) > 1: self.vector_reg   = module_argv[1]
        if len(module_argv) > 2: self.maxval       = int(module_argv[2],16)
        if len(module_argv) > 3: self.iterations   = int(module_argv[3])

        for r in self.gprs:
            self.gprs[r] = self.maxval
        if self.vector_reg is not None:
            self.gprs[self.vector_reg] = DEFAULT_VECTOR_MAXVAL

        self.logger.log( "\n[*] Configuration:" )
        self.logger.log( "    Mode               : %s" % ('random' if self.random_order else 'exhaustive') )
        self.logger.log( "    Hypercall vector in: %s" % self.vector_reg )
        self.logger.log( "    Max register value : 0x%X" % self.maxval )
        self.logger.log( "    Iterations         : %d\n" % self.iterations )

        return self.fuzz_generic_hypercalls()
        
