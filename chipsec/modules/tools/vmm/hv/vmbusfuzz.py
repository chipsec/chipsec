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
Hyper-V VMBus generic fuzzer

Usage:
    ``chipsec_main.py -i -m tools.vmm.hv.vmbusfuzz -a fuzz,<parameters>``

    Parameters:

    - ``all``          : Fuzzing all bytes
    - ``hv``           : Fuzzing HyperV message header
    - ``vmbus``        : Fuzzing HyperV message body / VMBUS message
    - ``<pos>,<size>`` : Fuzzing number of bytes at specific position

Examples:
    >>> chipsec_main.py -i -m tools.vmm.hv.vmbusfuzz -a fuzz,all -l log.txt

.. note::
    - The fuzzer is incompatible with native VMBus driver (``vmbus.sys``). To use it, remove ``vmbus.sys``
    - Returns a Warning by default
    - System may be in an unknown state, further evaluation may be needed

.. important::
    - This module is designed to run in a VM environment
    - Behavior on physical HW is undefined

"""

import sys
import traceback
from struct import pack
from random import getrandbits, choice
from chipsec.library.returncode import ModuleResult
from chipsec.modules.tools.vmm.common import session_logger, overwrite, get_int_arg
from chipsec.modules.tools.vmm.hv.vmbus import VMBusDiscovery, HyperV, RingBuffer

sys.stdout = session_logger(True, 'vmbusfuzz')


class VMBusFuzz(VMBusDiscovery):
    def __init__(self):
        VMBusDiscovery.__init__(self)
        self.training = False
        self.training_msginfo = []
        self.fuzzing = False
        self.fuzzing_rules = {}
        self.current_message = 0

    ##
    # hv_post_msg - Fuzzing a message to be sent
    ##
    def hv_post_msg(self, message):
        if self.training:
            self.training_msginfo.append(len(message))
        if self.fuzzing:
            if self.current_message in self.fuzzing_rules:
                rules = self.fuzzing_rules[self.current_message]
                for position in rules:
                    message = overwrite(message, rules[position], position)
            self.current_message += 1
        # Randomize leftover bytes. It shouldn't affect functionality.
        leftovers = ''.join(chr(getrandbits(8)) for _ in range(256 - len(message)))
        return HyperV.hv_post_msg(self, message + leftovers)

    def vmbus_test1_run(self):
        self.debug = False
        self.vmbus_request_offers()
        child_relid_list = sorted([value['child_relid'] for value in self.offer_channels.values()])

        if not self.fuzzing:
            for relid in child_relid_list:
                self.ringbuffers[relid] = RingBuffer()
                self.ringbuffers[relid].ringbuffer_alloc(4)
                self.ringbuffers[relid].gpadl = self.vmbus_get_next_gpadl()
                self.ringbuffers[relid].debug = False

        for relid in child_relid_list:
            self.vmbus_establish_gpadl(relid, self.ringbuffers[relid].gpadl, self.ringbuffers[relid].pfn)
            self.vmbus_open(relid, self.ringbuffers[relid].gpadl, self.ringbuffers[relid].send_size)

        if not self.fuzzing:
            self.print_supported_versions()
            self.print_offer_channels()
            self.print_created_gpadl()
            self.print_open_channels()
            self.print_events()

        for relid in child_relid_list:
            self.vmbus_close(relid)
            self.vmbus_teardown_gpadl(relid, self.ringbuffers[relid].gpadl)

        self.vmbus_rescind_all_offers()

    def run(self, module_argv):
        self.logger.start_test('Hyper-V VMBus fuzzer')

        if len(module_argv) > 0:
            command = module_argv[0]
        else:
            self.logger.log(self.__doc__.replace('`', ''))
            return

        cmdarg1 = module_argv[1] if len(module_argv) > 1 else 'all'
        cmdarg2 = module_argv[2] if len(module_argv) > 2 else '1'

        cmdarg1 = get_int_arg(cmdarg1) if cmdarg1 not in ['all', 'hv', 'vmbus'] else cmdarg1
        cmdarg2 = max(1, min(8, get_int_arg(cmdarg2)))

        self.debug = False
        self.promt = 'VMBUS'

        try:
            self.vmbus_init()
            self.scan_supported_versions()
            if len(self.supported_versions):
                version = choice(self.supported_versions.keys())
                self.vmbus_clear()
                self.vmbus_connect(version)
            self.training = True
            self.vmbus_test1_run()
            self.training = False

            if command == 'fuzz':
                m = 0
                for n in self.training_msginfo:
                    range_options = {'all': range(n), 'hv': range(0x10), 'vmbus': range(0x10, n)}
                    fuzzing_range = range_options[cmdarg1] if cmdarg1 in range_options else [cmdarg1]
                    fuzzing_range = [x for x in fuzzing_range if x < n]
                    for i in fuzzing_range:
                        randstr = pack('<Q', getrandbits(64))[:cmdarg2]
                        self.fuzzing_rules = {m: {i: randstr}}
                        self.logger.log(f'[VMBUS] Message: {m + 1:d}/{len(self.training_msginfo):d}  Fuzzing {len(randstr):d} byte(s): position {i:d} out of {n:d}')
                        self.vmbus_clear()
                        if len(self.supported_versions):
                            self.vmbus_connect(version)
                        self.current_message = 0
                        self.fuzzing = True
                        self.vmbus_test1_run()
                        self.fuzzing = False
                    m += 1
        except KeyboardInterrupt:
            self.logger.log('***** Control-C *****')
        except Exception:
            traceback.print_exc()
        finally:
            self.vmbus_rescind_all_offers()

        self.logger.log_information('Module completed')
        self.logger.log_warning('System may be in an unknown state, further evaluation may be needed.')
        self.result.setStatusBit(self.result.status.VERIFY)
        self.res = self.result.getReturnCode(ModuleResult.WARNING)
        return self.res
