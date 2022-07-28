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
Simple CPUID VMM emulation fuzzer

Usage:
    ``chipsec_main.py -i -m tools.vmm.cpuid_fuzz [-a random]``

    - ``random`` : Fuzz in random order (default is sequential)

Where:
    - ``[]``: optional line

Examples:
    >>> chipsec_main.py -i -m tools.vmm.cpuid_fuzz
    >>> chipsec_main.py -i -m tools.vmm.cpuid_fuzz -l log.txt
    >>> chipsec_main.py -i -m tools.vmm.cpuid_fuzz -a random

Additional options set within the module:
    - ``_NO_EAX_TO_FUZZ``        : No of EAX values to fuzz within each step
    - ``_EAX_FUZZ_STEP``         : Step to fuzz range of EAX values
    - ``_NO_ITERATIONS_TO_FUZZ`` : Number of iterations if `random` chosen
    - ``_FUZZ_ECX_RANDOM``       : Fuzz ECX with random values?
    - ``_MAX_ECX``               : Max ECX value
    - ``_EXCLUDE_CPUID``         : Exclude the following EAX values from fuzzing
    - ``_FLUSH_LOG_EACH_ITER``   : Flush log file after each iteration
    - ``_LOG_OUT_RESULTS``       : Log output results

.. note::
    - Returns a Warning by default
    - System may be in an unknown state, further evaluation may be needed

.. important::
    - This module is designed to run in a VM environment
    - Behavior on physical HW is undefined

"""

import random
from chipsec.module_common import BaseModule, ModuleResult

_MODULE_NAME = 'cpuid_fuzz'

#
# We will only be fuzzing _NO_EAX_TO_FUZZ range of EAX values each _EAX_FUZZ_STEP step
#
_NO_EAX_TO_FUZZ = 0x100
_EAX_FUZZ_STEP = 0x1000000

# Number of iterations if value is Randomly chosen
_NO_ITERATIONS_TO_FUZZ = 0x1000000

# Control values to be passed in ECX
_FUZZ_ECX_RANDOM = False
# Max value of ECX when fuzzed sequentially
_MAX_ECX = 0x100

# Exclude CPUID EAX which cause VM hang/crash
_EXCLUDE_CPUID = []

# Flush log file before each fuzz iteration
_FLUSH_LOG_EACH_ITER = False
# Log values of EAX, EBX, ECX, EDX which CPUID returns
_LOG_OUT_RESULTS = False


class cpuid_fuzz (BaseModule):

    def fuzz_CPUID(self, eax_start, random_order=False):
        eax_range = _NO_EAX_TO_FUZZ
        eax_end = eax_start + eax_range
        self.logger.log("[*] Fuzzing CPUID with EAX in range 0x{:08X}:0x{:08X}..".format(eax_start, eax_end))
        it = 0
        if random_order:
            it_max = _NO_ITERATIONS_TO_FUZZ
        else:
            it_max = eax_range

        while it < it_max:
            if random_order:
                eax = random.randint(eax_start, eax_end)
            else:
                eax = eax_start + it
            if _FLUSH_LOG_EACH_ITER:
                self.logger.flush()
            if eax not in _EXCLUDE_CPUID:
                self.logger.log("[*] CPUID EAX: 0x{:08X}".format(eax))
                if _FUZZ_ECX_RANDOM:
                    ecx = random.randint(0, 0xFFFFFFFF)
                    (r_eax, r_ebx, r_ecx, r_edx) = self.cs.cpu.cpuid(eax, ecx)
                else:
                    for ecx in range(_MAX_ECX):
                        self.logger.log("  > ECX: 0x{:08X}".format(ecx))
                        if _FLUSH_LOG_EACH_ITER:
                            self.logger.flush()
                        (r_eax, r_ebx, r_ecx, r_edx) = self.cs.cpu.cpuid(eax, ecx)
                        if _LOG_OUT_RESULTS:
                            self.logger.log("    Out: EAX=0x{:08X}, EBX=0x{:08X}, ECX=0x{:08X}, EDX=0x{:08X}".format(r_eax, r_ebx, r_ecx, r_edx))
            it += 1
        return True

    def run(self, module_argv):
        self.logger.start_test("CPUID Fuzzer")

        _random_order = False
        if (len(module_argv) > 0) and ('random' == module_argv[0]):
            _random_order = True

        self.logger.log("[*] Configuration:")
        self.logger.log("    Mode: {}".format('random' if _random_order else 'sequential'))
        self.logger.log("    Step to fuzz range of EAX values (_EAX_FUZZ_STEP): 0x{:X}".format(_EAX_FUZZ_STEP))
        self.logger.log("    No of EAX values to fuzz within each step (_NO_EAX_TO_FUZZ): 0x{:X}".format(_NO_EAX_TO_FUZZ))
        self.logger.log("    Fuzz ECX with random values? (_FUZZ_ECX_RANDOM): {:d}".format(_FUZZ_ECX_RANDOM))
        self.logger.log("    Max ECX value (_MAX_ECX): 0x{:08X}".format(_MAX_ECX))
        self.logger.log("    Exclude the following EAX values from fuzzing (_EXCLUDE_CPUID): {}".format(str(_EXCLUDE_CPUID)))
        self.logger.log("    Flush log file after each iteration (_FLUSH_LOG_EACH_ITER): {:d}".format(_FLUSH_LOG_EACH_ITER))
        self.logger.log("    Log output results (_LOG_OUT_RESULTS): {:d}".format(_LOG_OUT_RESULTS))

        steps = 0x100000000 // _EAX_FUZZ_STEP
        for s in range(steps):
            self.fuzz_CPUID(s * _EAX_FUZZ_STEP, _random_order)

        self.logger.log_information('Module completed')
        self.logger.log_warning('System may be in an unknown state, further evaluation may be needed.')
        self.res = ModuleResult.WARNING
        return self.res
