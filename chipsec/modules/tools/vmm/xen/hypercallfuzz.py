# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
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
Xen hypercall fuzzer

Usage:
    ``chipsec_main.py -i -m tools.vmm.xen.hypercallfuzz -a <mode>[,<vector>,<iterations>]``

    - ``mode``                       : fuzzing mode

        * ``help``                 : Prints this help
        * ``info``                 : Hypervisor information
        * ``fuzzing``              : Fuzzing specified hypercall
        * ``fuzzing-all``          : Fuzzing all hypercalls
        * ``fuzzing-all-randomly`` : Fuzzing random hypercalls
    - ``<vector>``                 : Code or name of a hypercall to be fuzzed (use info)
    - ``<iterations>``             : Number of fuzzing iterations

Examples:
    >>> chipsec_main.py -i -m tools.vmm.xen.hypercallfuzz -a fuzzing,10 -l log.txt
    >>> chipsec_main.py -i -m tools.vmm.xen.hypercallfuzz -a fuzzing-all,50 -l log.txt
    >>> chipsec_main.py -i -m tools.vmm.xen.hypercallfuzz -a fuzzing-all-randomly,10,0x10000000 -l log.txt

.. note::
    - Returns a Warning by default
    - System may be in an unknown state, further evaluation may be needed

.. important::
    - This module is designed to run in a VM environment
    - Behavior on physical HW is undefined

"""

from chipsec.modules.tools.vmm.xen.define import *
from chipsec.module_common import BaseModule
from chipsec.library.returncode import ModuleResult
from chipsec.modules.tools.vmm.xen.hypercall import XenHypercall


class HypercallFuzz(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)

    def usage(self):
        self.logger.log(self.__doc__.replace('`', ''))
        return

    def get_int(self, arg, base=10, defvalue=10000):
        try:
            value = int(arg, base)
        except ValueError:
            self.logger.log_error(f'Invalid integer parameter: \'{arg}\' (using default value: {defvalue:d})')
            value = defvalue
        return value

    def run(self, module_argv):
        self.logger.start_test('Xen Hypervisor Hypercall Fuzzer')
        command = module_argv[0] if len(module_argv) > 0 else ''
        arg1 = module_argv[1] if len(module_argv) > 1 else ''
        arg2 = module_argv[2] if len(module_argv) > 2 else ''

        xen = XenHypercall()
        xen.prompt = 'CHIPSEC'
        xen.debug = False

        if command == 'help':
            self.usage()
        elif command == 'info':
            info = xen.get_hypervisor_info()
            if len(info) > 0:
                xen.hypervisor_present = True
                xen.print_hypervisor_info(info)
                xen.scan_hypercalls(range(256))
                xen.print_hypercall_status()

        elif command == 'fuzzing':
            name2code = {v.lower(): k for k, v in hypercall_names.items()}
            try:
                code = int(arg1, 16)
            except ValueError:
                if arg1.lower() not in name2code:
                    self.logger.log_error(f'Unknown hypercall: \'{arg1}\'')
                    self.result.setStatusBit(self.result.status.UNSUPPORTED_OPTION)
                    return self.result.getReturnCode(ModuleResult.ERROR)
                code = name2code[arg1.lower()]
            count = self.get_int(arg2)
            xen.fuzz_hypercall(code, count)

        elif command in ['fuzzing-all', 'fuzzing-all-randomly']:
            count = self.get_int(arg1)
            xen.scan_hypercalls(range(256))
            xen.print_hypercall_status()
            self.logger.log('\nStart fuzzing ...\n')
            excluded = [MEMORY_OP, CONSOLE_IO, GRANT_TABLE_OP, SCHED_OP]
            vectors = sorted([x for x in xen.hypercalls.keys() if x not in excluded])
            if command == 'fuzzing-all':
                for vector in vectors:
                    xen.fuzz_hypercall(vector, count)
            else:
                xen.fuzz_hypercalls_randomly(vectors, count)
        else:
            self.logger.log(f'Invalid command: {command}\n')
            self.usage()

        self.logger.log_information('Module completed')
        self.logger.log_warning('System may be in an unknown state, further evaluation may be needed.')
        self.result.setStatusBit(self.result.status.POTENTIALLY_VULNERABLE)
        self.res = self.result.getReturnCode(ModuleResult.WARNING)
        return self.res
