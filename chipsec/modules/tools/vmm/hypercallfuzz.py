# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2020, Intel Corporation
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# Contact information:
# chipsec@intel.com
#


"""
Pretty simple VMM hypercall fuzzer

Usage:
    ``chipsec_main.py -i -m tools.vmm.hypercallfuzz [-a <mode>,<vector_reg>,<maxval>,<iterations>]``

    - ``mode``           : Hypercall fuzzing mode
        * ``exhaustive`` : Fuzz all arguments exhaustively in range ``[0:<maxval>]`` (default)
        * ``random``     : Send random values in all registers in range ``[0:<maxval>]``
    - ``vector_reg``     : Hypercall vector register
    - ``maxval``         : Maximum value of each register
    - ``iterations``     : Number of iterations in random mode

Where:
    - ``[]``: optional line

Examples:
    >>> chipsec_main.py -i -m tools.vmm.hypercallfuzz
    >>> chipsec_main.py -i -m tools.vmm.hypercallfuzz -a random,22,0xFFFF,1000

Additional options set within the module:
    - ``DEFAULT_VECTOR_MAXVAL``     : Default maximum value
    - ``DEFAULT_MAXVAL_EXHAUSTIVE`` : Default maximum value for exhaustive testing
    - ``DEFAULT_MAXVAL_RANDOM``     : Default maximum value for random testing
    - ``DEFAULT_RANDOM_ITERATIONS`` : Default iterations for random testing
    - ``_FLUSH_LOG_EACH_ITER``      : Set to flush log after each iteration
    - ``_LOG_ALL_GPRS``             : Display log of each iteration values

.. note::
    - Returns a Warning by default
    - System may be in an unknown state, further evaluation may be needed

.. important::
    - This module is designed to run in a VM environment
    - Behavior on physical HW is undefined

"""

import random
import time

from chipsec.module_common import BaseModule
from chipsec.library.returncode import ModuleResult
from chipsec.hal.vmm import VMM

DEFAULT_VECTOR_MAXVAL = 0xFF

DEFAULT_MAXVAL_EXHAUSTIVE = 0xFF
DEFAULT_MAXVAL_RANDOM = 0xFFFFFFFF

DEFAULT_RANDOM_ITERATIONS = 0x7FFFFFFF

# Flush log file before each port
_FLUSH_LOG_EACH_ITER = False
_LOG_ALL_GPRS = True

GPRS = {'rax': 0, 'rbx': 0, 'rcx': 0, 'rdx': 0, 'rdi': 0, 'rsi': 0, 'r8': 0, 'r9': 0, 'r10': 0, 'r11': 0}


class hypercallfuzz(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.vmm = VMM(self.cs)
        self.random_order = True
        self.gprs = GPRS
        self.vector_reg = None
        self.iterations = DEFAULT_RANDOM_ITERATIONS
        self.maxval = DEFAULT_MAXVAL_RANDOM

    def is_supported(self):
        return True

    def fuzz_generic_hypercalls(self):
        _fmt = '{:02X}' if self.maxval <= 0xFF else ('{:04X}' if self.maxval <= 0xFFFF else ('{:08X}' if self.maxval <= 0xFFFFFFFF else '{:016X}'))
        _str = f'{{:d}} hcall rax={_fmt},rbx={_fmt},rcx={_fmt},rdx={_fmt},rdi={_fmt},rsi={_fmt},r8={_fmt},r9={_fmt},r10={_fmt},r11={_fmt}'

        t = time.time()
        if self.random_order:

            self.logger.log(f'[*] Fuzzing {self.iterations:d} random hypercalls with random arguments...')
            for it in range(self.iterations):
                rax = random.randint(0, self.gprs['rax'])
                rbx = random.randint(0, self.gprs['rbx'])
                rcx = random.randint(0, self.gprs['rcx'])
                rdx = random.randint(0, self.gprs['rdx'])
                rdi = random.randint(0, self.gprs['rdi'])
                rsi = random.randint(0, self.gprs['rsi'])
                r8 = random.randint(0, self.gprs['r8'])
                r9 = random.randint(0, self.gprs['r9'])
                r10 = random.randint(0, self.gprs['r10'])
                r11 = random.randint(0, self.gprs['r11'])
                if _LOG_ALL_GPRS:
                    self.logger.log(_str.format(it, rax, rbx, rcx, rdx, rdi, rsi, r8, r9, r10, r11))
                else:
                    self.logger.log(f'{it:d} hcall')
                if _FLUSH_LOG_EACH_ITER:
                    self.logger.flush()
                try:
                    self.vmm.hypercall(rax, rbx, rcx, rdx, rdi, rsi, r8, r9, r10, r11)
                except:
                    pass
        else:
            it = 0
            self.logger.log('[*] Fuzzing hypercalls with arguments exhaustively...')
            for rax in range(self.gprs['rax']):
                for rbx in range(self.gprs['rbx']):
                    for rcx in range(self.gprs['rcx']):
                        for rdx in range(self.gprs['rdx']):
                            for rdi in range(self.gprs['rdi']):
                                for rsi in range(self.gprs['rsi']):
                                    for r8 in range(self.gprs['r8']):
                                        for r9 in range(self.gprs['r9']):
                                            for r10 in range(self.gprs['r10']):
                                                for r11 in range(self.gprs['r11']):
                                                    if _LOG_ALL_GPRS:
                                                        self.logger.log(_str.format(it, rax, rbx, rcx, rdx, rdi, rsi, r8, r9, r10, r11))
                                                    else:
                                                        self.logger.log(f'{it:d} hcall')
                                                    if _FLUSH_LOG_EACH_ITER:
                                                        self.logger.flush()
                                                    try:
                                                        self.vmm.hypercall(rax, rbx, rcx, rdx, rdi, rsi, r8, r9, r10, r11)
                                                        it += 1
                                                    except:
                                                        pass

        self.logger.log(f'[*] Finished fuzzing: time elapsed {time.time() - t:.3f}')

    def run(self, module_argv):
        self.logger.start_test('Dumb VMM hypercall fuzzer')

        if len(module_argv) > 0:
            self.random_order = module_argv[0].lower() == 'random'
        self.maxval = DEFAULT_MAXVAL_RANDOM if self.random_order else DEFAULT_MAXVAL_EXHAUSTIVE
        if len(module_argv) > 1:
            self.vector_reg = module_argv[1]
        if len(module_argv) > 2:
            self.maxval = int(module_argv[2], 16)
        if len(module_argv) > 3:
            self.iterations = int(module_argv[3])

        for r in self.gprs:
            self.gprs[r] = self.maxval
        if self.vector_reg is not None:
            self.gprs[self.vector_reg] = DEFAULT_VECTOR_MAXVAL

        self.logger.log('\n[*] Configuration:')
        self.logger.log(f'    Mode               : {"random" if self.random_order else "exhaustive"}')
        self.logger.log(f'    Hypercall vector in: {self.vector_reg}')
        self.logger.log(f'    Max register value : 0x{self.maxval:X}')
        self.logger.log(f'    Iterations         : {self.iterations:d}\n')

        self.res = self.fuzz_generic_hypercalls()

        self.logger.log_information('Module completed')
        self.logger.log_warning('System may be in an unknown state, further evaluation may be needed.')
        self.result.setStatusBit(self.result.status.VERIFY)
        return self.result.getReturnCode(ModuleResult.WARNING)
