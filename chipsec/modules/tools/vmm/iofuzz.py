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
Simple port I/O VMM emulation fuzzer

Usage:
    ``chipsec_main.py -i -m tools.vmm.iofuzz [-a <mode>,<count>,<iterations>]``

    - ``<mode>``         : SMI handlers testing mode
        - ``exhaustive`` : Fuzz all I/O ports exhaustively (default)
        - ``random``     : Fuzz randomly chosen I/O ports
    - ``<count>``        : Number of times to write to each port (default = 1000)
    - ``<iterations>``   : Number of I/O ports to fuzz (default = 1000000 in random mode)

Where:
    - ``[]``: optional line

Examples:
    >>> chipsec_main.py -i -m tools.vmm.iofuzz
    >>> chipsec_main.py -i -m tools.vmm.iofuzz -a random,9000,4000000

Additional options set within the module:
    - ``MAX_PORTS``                 : Maximum ports
    - ``MAX_PORT_VALUE``            : Maximum port value to use
    - ``DEFAULT_PORT_WRITE_COUNT``  : Default port write count if not specified with switches
    - ``DEFAULT_RANDOM_ITERATIONS`` : Default port write iterations if not specified with switches
    - ``_FLUSH_LOG_EACH_ITER``      : Flush log after each iteration
    - ``_FUZZ_SPECIAL_VALUES``      : Specify to use 1-2-4 byte values
    - ``_EXCLUDE_PORTS``            : Ports to exclude (list)

.. note::
    - Returns a Warning by default
    - System may be in an unknown state, further evaluation may be needed

.. important::
    - This module is designed to run in a VM environment
    - Behavior on physical HW is undefined

"""

import random

from chipsec.module_common import BaseModule
from chipsec.library.returncode import ModuleResult

MAX_PORTS = 0x10000
MAX_PORT_VALUE = 0xFF
DEFAULT_PORT_WRITE_COUNT = 1000
DEFAULT_RANDOM_ITERATIONS = 1000000

# Flush log file before each port
_FLUSH_LOG_EACH_ITER = False

# Control values to be written to each port
_FUZZ_SPECIAL_VALUES = True

# List I/O port numbers you want to exclude from fuzzing
_EXCLUDE_PORTS = []


class iofuzz(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)

    def fuzz_ports(self, iterations, write_count, random_order=False):

        if random_order:
            self.logger.log(f'[*] Fuzzing randomly chosen {iterations:d} I/O ports..\n')
        else:
            self.logger.log(f'[*] Fuzzing I/O ports in a range 0:0x{iterations - 1:X}..\n')

        io_addr = 0
        for it in range(iterations):

            if _FLUSH_LOG_EACH_ITER:
                self.logger.flush()

            if random_order:
                io_addr = random.randint(0, MAX_PORTS)
            else:
                io_addr = it

            if io_addr in _EXCLUDE_PORTS:
                self.logger.log(f'[*] Skipping port 0x{io_addr:04X}')
                continue

            self.logger.log(f'[*] Fuzzing I/O port 0x{io_addr:04X}')

            self.logger.log('    Reading port')
            port_value = self.cs.io.read_port_byte(io_addr)

            if _FUZZ_SPECIAL_VALUES:
                self.logger.log('    Writing special 1-2-4 byte values')
                try:
                    self.cs.io.write_port_byte(io_addr, port_value)
                    self.cs.io.write_port_byte(io_addr, (~port_value) & 0xFF)
                    self.cs.io.write_port_byte(io_addr, 0xFF)
                    self.cs.io.write_port_byte(io_addr, 0x00)
                    self.cs.io.write_port_byte(io_addr, 0x5A)
                    self.cs.io.write_port_word(io_addr, 0xFFFF)
                    self.cs.io.write_port_word(io_addr, 0x0000)
                    self.cs.io.write_port_word(io_addr, 0x5AA5)
                    self.cs.io.write_port_dword(io_addr, 0xFFFFFFFF)
                    self.cs.io.write_port_dword(io_addr, 0x00000000)
                    self.cs.io.write_port_word(io_addr, 0x5AA55AA5)
                except:
                    pass

            self.logger.log(f'    Writing values 0..{MAX_PORT_VALUE:X} ({write_count:d} times each)')
            for v in range(MAX_PORT_VALUE + 1):
                for _ in range(write_count):
                    try:
                        self.cs.io.write_port_byte(io_addr, v)
                    except:
                        pass

        self.result.setStatusBit(self.result.status.VERIFY)
        return self.result.getReturnCode(ModuleResult.WARNING)


    def run(self, module_argv):
        self.logger.start_test('I/O port fuzzer')

        _random_order = (len(module_argv) > 0) and ('random' == module_argv[0].lower())
        write_count = int(module_argv[1]) if len(module_argv) > 1 else DEFAULT_PORT_WRITE_COUNT
        if len(module_argv) > 2:
            iterations = int(module_argv[2])
        else:
            iterations = DEFAULT_RANDOM_ITERATIONS if _random_order else MAX_PORTS

        self.logger.log('\n[*] Configuration:')
        self.logger.log(f'    Mode             : {"random" if _random_order else "exhaustive"}')
        self.logger.log(f'    Write count      : {write_count:d}')
        self.logger.log(f'    Ports/iterations : {iterations:d}\n')

        self.res = self.fuzz_ports(iterations, write_count, _random_order)

        self.logger.log_information('Module completed')
        self.logger.log_warning('System may be in an unknown state, further evaluation may be needed.')
        return self.res
