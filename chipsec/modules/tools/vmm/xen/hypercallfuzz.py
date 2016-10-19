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
Xen hypercall fuzzer

Usage:
  ``chipsec_main.py -i -m tools.vmm.xen.hypercallfuzz \``
  ``-a <mode>[,<vector>,<iterations>] -l log.txt``

    - ``mode``				fuzzing mode

        * ``= help``			prints this help
        * ``= info``			hypervisor information
        * ``= fuzzing``			fuzzing specified hypercall
        * ``= fuzzing-all``		fuzzing all hypercalls
        * ``= fuzzing-all-randomly``	fuzzing random hypercalls
    - ``vector``			code or name of a hypercall to be fuzzed (use info)
    - ``iterations``			number of fuzzing iterations

Examples:

  ``chipsec_main.py -i -m tools.vmm.xen.hypercallfuzz -a sched_op,10 -l log.txt``
  ``chipsec_main.py -i -m tools.vmm.xen.hypercallfuzz -a xen_version,50 -l log.txt``
  ``chipsec_main.py -i -m tools.vmm.xen.hypercallfuzz -a set_timer_op,10,0x10000000 -l log.txt``
"""

from define                           import *
from hypercall                        import *
from chipsec.hal.vmm                  import *
from chipsec.module_common            import *
from chipsec.modules.tools.vmm.common import *

class HypercallFuzz (BaseModule):

    def usage(self):
        self.logger.log('')
        self.logger.log('  Usage:' )
        self.logger.log('    chipsec_main.py -i -m tools.vmm.xen.hypercallfuzz -a <mode>[,<hypercall>,<iterations>] -l log.txt' )
        self.logger.log('      <mode>			fuzzing mode' )
        self.logger.log('        = help			prints this help' )
        self.logger.log('        = info			hypervisor information' )
        self.logger.log('        = fuzzing		fuzzing hypercall specified with <vector>' )
        self.logger.log('        = fuzzing-all		fuzzing all hypercalls' )
        self.logger.log('        = fuzzing-all-randomly	fuzzing random hypercalls' )
        self.logger.log('      <vector>			code or name of a hypercall to be fuzzed (use info)' )
        self.logger.log('      <iterations>		number of fuzzing iterations' )
        return

    def get_int(self, arg, base = 10, defvalue = 10000):
        try:
            value = int(arg, base)
        except ValueError:
            self.logger.error( "Invalid integer parameter: '%s' (using default value: %d)" % (arg, defvalue))
            value = defvalue
        return value

    def run( self, module_argv ):
        self.logger.start_test('Xen Hypervisor Hypercall Fuzzer')
        command = module_argv[0] if len(module_argv) > 0 else ''
        arg1    = module_argv[1] if len(module_argv) > 1 else ''
        arg2    = module_argv[2] if len(module_argv) > 2 else ''

        xen = XenHypercall()
        xen.promt = 'CHIPSEC'
        xen.debug = False

        ##
        ## XSA-188 Workaround
        ##
        #(cntl_va, cntl_pa) = self.cs.mem.alloc_physical_mem(0x1000, 0xFFFFFFFFFFFFFFFF)
        #(args_va, args_pa) = self.cs.mem.alloc_physical_mem(0x1000, 0xFFFFFFFFFFFFFFFF)
        #cntl = '\x00' * 4096
        #args = struct.pack('<QLLQ', cntl_pa >> 12, 0, 0, 0)
        #self.cs.mem.write_physical_mem(args_pa, len(args), args)
        #self.cs.mem.write_physical_mem(cntl_pa, len(cntl), cntl)
        #result = xen.hypercall([EVENT_CHANNEL_OP, EVTCHOP_INIT_CONTROL, args_va])
        #if result['status'] == XEN_STATUS_SUCCESS:
        #    self.logger.log('Event channel control block has been initialized !')

        if command == 'help':
            self.usage()
        elif command == 'info':
            info = xen.get_hypervisor_info()
            if len(info) > 0:
                xen.hypervisor_present = True
                xen.print_hypervisor_info(info)
                xen.scan_hypercalls(xrange(256))
                xen.print_hypercall_status()
 
        elif command == 'fuzzing':
            name2code = {v.lower():k for k,v in hypercall_names.items()}
            try:
                code = int(arg1, 16)
            except ValueError:
                if arg1.lower() not in name2code:
                    self.logger.error( "Unknown hypercall: '%s'" % arg1)
                    return ModuleResult.ERROR
                code = name2code[arg1.lower()]
            count = self.get_int(arg2)
            xen.fuzz_hypercall(code, count)

        elif command in ['fuzzing-all', 'fuzzing-all-randomly']:
            count = self.get_int(arg1)
            xen.scan_hypercalls(xrange(256))
            xen.print_hypercall_status()
            self.logger.log('\nStart fuzzing ...\n')
            #excluded = [MEMORY_OP, CONSOLE_IO, GRANT_TABLE_OP, SCHED_OP, EVENT_CHANNEL_OP]
            excluded = [MEMORY_OP, CONSOLE_IO, GRANT_TABLE_OP, SCHED_OP]
            vectors = sorted([x for x in xen.hypercalls.keys() if x not in excluded])
            if command == 'fuzzing-all':
                for vector in vectors:
                    xen.fuzz_hypercall(vector, count)
            else:
                xen.fuzz_hypercalls_randomly(vectors, count)
        else:
            self.logger.log('Invalid command: %s\n' % command)
            self.usage()

        return ModuleResult.PASSED
