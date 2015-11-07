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
Simple port I/O VMM emulation fuzzer

 Usage:
   ``chipsec_main.py -i -m tools.vmm.iofuzz [ -a <mode>,<count>,<iterations> ] -l iofuzz.log``
"""
import random

from chipsec.module_common import *

MAX_PORTS = 0x10000
MAX_PORT_VALUE = 0xFF
DEFAULT_PORT_WRITE_COUNT  = 1000
DEFAULT_RANDOM_ITERATIONS = 1000000

#_READ_PORT = True

# Flush log file before each port
_FLUSH_LOG_EACH_ITER = False

# Control values to be written to each port
_FUZZ_SPECIAL_VALUES = True
_FUZZ_RANDOM_VALUE   = True

# List I/O port numbers you want to exclude from fuzzing
_EXCLUDE_PORTS = []


class iofuzz(BaseModule):

    def fuzz_ports( self, iterations, write_count, random_order=False ):

        if random_order: self.logger.log( "[*] Fuzzing randomly chosen %d I/O ports..\n" % iterations )
        else: self.logger.log( "[*] Fuzzing I/O ports in a range 0:0x%X..\n" % (iterations-1) )

        io_addr = 0
        for it in range(iterations):

            if _FLUSH_LOG_EACH_ITER: self.logger.flush()

            if random_order: io_addr = random.randint( 0, MAX_PORTS )
            else:            io_addr = it

            if io_addr in _EXCLUDE_PORTS:
                self.logger.log( "[*] skipping port 0x%04X" % io_addr )
                continue

            self.logger.log( "[*] fuzzing I/O port 0x%04X" % io_addr )

            self.logger.log( "    reading port" )
            port_value = self.cs.io.read_port_byte( io_addr )

            if _FUZZ_SPECIAL_VALUES:
                self.logger.log( "    writing special 1-2-4 byte values" )
                try:
                    self.cs.io.write_port_byte ( io_addr, port_value )
                    self.cs.io.write_port_byte ( io_addr, ((~port_value) & 0xFF) )
                    self.cs.io.write_port_byte ( io_addr, 0xFF )
                    self.cs.io.write_port_byte ( io_addr, 0x00 )
                    self.cs.io.write_port_byte ( io_addr, 0x5A )
                    self.cs.io.write_port_word ( io_addr, 0xFFFF )
                    self.cs.io.write_port_word ( io_addr, 0x0000 )
                    self.cs.io.write_port_word ( io_addr, 0x5AA5 )
                    self.cs.io.write_port_dword( io_addr, 0xFFFFFFFF )
                    self.cs.io.write_port_dword( io_addr, 0x00000000 )
                    self.cs.io.write_port_word ( io_addr, 0x5AA55AA5 )
                except: pass

            self.logger.log( "    writing values 0..%X (%d times each)" % (MAX_PORT_VALUE,write_count) )
            for v in range(MAX_PORT_VALUE+1):
                for n in range(write_count):
                    try: self.cs.io.write_port_byte( io_addr, v )
                    except: pass
                    pass

        return ModuleResult.PASSED

    def run( self, module_argv ):

        self.logger.start_test( "I/O port fuzzer" )
        self.logger.log( "Usage: chipsec_main -m tools.vmm.iofuzz [ -a <mode>,<count>,<iterations> ]" )
        self.logger.log( "  mode            SMI handlers testing mode" )
        self.logger.log( "    = exhaustive  fuzz all I/O ports exhaustively (default)")
        self.logger.log( "    = random      fuzz randomly chosen I/O ports" )
        self.logger.log( "  count           how many times to write to each port (default = %d)" % DEFAULT_PORT_WRITE_COUNT )
        self.logger.log( "  iterations      number of I/O ports to fuzz (default = %d in random mode)" % DEFAULT_RANDOM_ITERATIONS )

        _random_order = (len(module_argv) > 0 and 'random' == module_argv[0].lower())
        write_count   = int(module_argv[1]) if len(module_argv) > 1 else DEFAULT_PORT_WRITE_COUNT
        if len(module_argv) > 2: iterations = int(module_argv[2])
        else:                    iterations = DEFAULT_RANDOM_ITERATIONS if _random_order else MAX_PORTS

        self.logger.log( "\n[*] Configuration:" )
        self.logger.log( "    Mode            : %s" % ('random' if _random_order else 'exhaustive') )
        self.logger.log( "    Write count     : %d" % write_count )
        self.logger.log( "    Ports/iterations: %d\n" % iterations )

        return self.fuzz_ports( iterations, write_count, _random_order )
        
