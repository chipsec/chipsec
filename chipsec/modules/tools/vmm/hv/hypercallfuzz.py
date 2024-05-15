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
Hyper-V hypercall fuzzer

Usage:
  ``chipsec_main.py -i -m tools.vmm.hv.hypercall -a <mode>[,<vector>,<iterations>] -l log.txt``

    - ``mode``			fuzzing mode

        * ``= status-fuzzing``	finding parameters with hypercall success status
        * ``= params-info``	shows input parameters valid ranges
        * ``= params-fuzzing``	parameters fuzzing based on their valid ranges
        * ``= custom-fuzzing``	fuzzing of known hypercalls
    - ``vector``		hypercall vector
    - ``iterations``		number of hypercall iterations

Note: the fuzzer is incompatible with native VMBus driver (``vmbus.sys``). To use it, remove ``vmbus.sys``
"""
from chipsec.modules.tools.vmm.hv.define import *
from chipsec.modules.tools.vmm.hv.hypercall import *
from chipsec.module_common import *

# Hypercall vectors excluded from scan/fuzzing
excluded_hypercalls_from_scan = []
excluded_hypercalls_from_fuzzing = excluded_hypercalls_from_scan + [HV_POST_MESSAGE]


class HypercallFuzz(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)

    def usage(self):
        print('  Usage:')
        print('    chipsec_main.py -i -m tools.vmm.hv.hypercall [-a mode,vector,iterations]')
        print('      mode                fuzzing mode')
        print('        = status-fuzzing  finding parameters with hypercall success status')
        print('        = params-info     shows input parameters valid ranges')
        print('        = params-fuzzing  parameters fuzzing based on their valid ranges')
        print('        = custom-fuzzing  fuzzing of known hypercalls')
        print('      vector              hypercall vector')
        print('      iterations          number of hypercall iterations')
        print('  Note: the fuzzer is incompatible with native VMBus driver (vmbus.sys). To use it, remove vmbus.sys')
        return

    def run(self, module_argv):
        self.logger.start_test("Hyper-V hypercall fuzzer")

        if len(module_argv) > 0:
            command = module_argv[0]
        else:
            self.usage()
            return

        callnum = get_int_arg(module_argv[1]) if len(module_argv) > 1 and module_argv[1] != '' else 'all'
        testnum = get_int_arg(module_argv[2]) if len(module_argv) > 2 and module_argv[2] != '' else 10000000

        hv = HyperVHypercall()
        hv.promt = 'CHIPSEC'

        hv.print_hypervisor_info()

        if hv.hypervisor_present:
            hv.scan_partitionid(range(0x0, 0x100))
            hv.scan_connectionid(range(0x00000, 0x00100) + range(0x10000, 0x10100))

            # Scans for implemented hypercalls and discovers their interface
            hypercalls_for_scanning = list(set(range(0x100)) - set(excluded_hypercalls_from_scan))
            hv.scan_hypercalls(hypercalls_for_scanning)

        if callnum == 'all':
            hypercalls = list(set(hv.hv_hypercalls.keys()) - set(excluded_hypercalls_from_fuzzing))
        else:
            hypercalls = [callnum]

        if command == 'info':
            if hv.hypervisor_present:
                # Print Synthetic MSRs
                hv.print_synthetic_msrs()

                # Print Partition IDs
                hv.print_partitionid()

                # Print Connection IDs
                hv.print_connectionid([])
                hv.print_partition_properties()

                # Print discovered hypercalls and their interface
                hv.print_hypercall_status()

        elif command == 'status-fuzzing':
            for i in hypercalls:
                hv.promt = f'HYPERCALL {i:04X}'
                hv.msg('[*] Scan hypercall for success status')
                hv.scan_for_success_status(i, testnum)

        elif command == 'params-info':
            for i in hypercalls:
                hv.promt = f'HYPERCALL {i:04X}'
                if (hv.hv_hypercalls[i][2] == HV_STATUS_SUCCESS):
                    hv.msg('Scan hypercall for input parameters')
                    hv.scan_input_parameters(i, 32)
                    hv.print_input_parameters(i, 32, [HV_STATUS_SUCCESS])

        elif command == 'params-fuzzing':
            for i in hypercalls:
                hv.promt = f'HYPERCALL {i:04X}'
                if (hv.hv_hypercalls[i][2] == HV_STATUS_SUCCESS):
                    hv.msg('Fuzzing hypercall for input parameters')
                    hv.scan_input_parameters(i, 32)
                    hv.print_input_parameters(i, 32, [HV_STATUS_SUCCESS])
                    hv.input_parameters_fuzzing(i, 32, [HV_STATUS_SUCCESS], testnum)

        elif command == 'custom-fuzzing':
            for i in hypercalls:
                hv.promt = f'HYPERCALL {i:04X}'
                hv.custom_fuzzing(i, testnum)

        else:
            hv.err('Invalid mode!')
            self.usage()

        self.result.setStatusBit(self.result.status.SUCCESS)
        return self.result.getReturnCode(ModuleResult.PASSED)
