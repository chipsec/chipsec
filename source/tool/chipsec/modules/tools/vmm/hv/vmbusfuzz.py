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
Hyper-V VMBus generic fuzzer

 Usage:
   ``chipsec_main.py -i -m tools.vmm.hv.vmbusfuzz -a fuzz,<parameters>``
   ``  parameters:'
   ``    all          fuzzing all bytes'
   ``    hv           fuzzing HyperV message header'
   ``    vmbus        fuzzing HyperV message body / VMBUS message'
   ``    <pos>,<size> fuzzing number of bytes at specific position'

Note: the fuzzer is incompatibe with native VMBus driver (vmbus.sys). To use it, remove vmbus.sys
"""
from struct import *
from random import *
from define import *
from chipsec.modules.tools.vmm.common import *
from vmbus  import *
import chipsec_util

sys.stdout = session_logger(True, 'vmbusfuzz')

class VMBusFuzz(VMBusDiscovery):
    def __init__(self):
        VMBusDiscovery.__init__(self)
        self.training         = False
        self.training_msginfo = []
        self.fuzzing          = False
        self.fuzzing_rules    = {}
        self.current_message  = 0

    ##
    ##  hv_post_msg - Fuzzing a message to be sent
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
        ## Randomize leftover bytes. It shouldn't affect functionality.
        leftovers = ''.join(chr(getrandbits(8)) for i in range(256 - len(message)))
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
        #if not self.fuzzing:
        #for i in self.ringbuffers:
        #    self.ringbuffers[i].ringbuffer_free()

    def usage(self):
        self.logger.log('  Usage:')
        self.logger.log('    chipsec_main.py -i -m tools.vmm.hv.vmbusfuzz -a fuzz,<parameters>')
        self.logger.log('      parameters:')
        self.logger.log('        all          fuzzing all bytes')
        self.logger.log('        hv           fuzzing HyperV message header')
        self.logger.log('        vmbus        fuzzing HyperV message body / VMBUS message')
        self.logger.log('        <pos>,<size> fuzzing number of bytes at specific position')
        self.logger.log('  Note: the fuzzer is incompatibe with native VMBus driver (vmbus.sys). To use it, remove vmbus.sys')

    def run(self, module_argv):
        self.logger.start_test( "Hyper-V VMBus fuzzer" )

        if len(module_argv) > 0:
            command = module_argv[0]
        else:
            self.usage()
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
                        self.logger.log('[VMBUS] Message: %d/%d  Fuzzing %d byte(s): position %d out of %d' % (m + 1, len(self.training_msginfo), len(randstr), i, n))
                        self.vmbus_clear()
                        if len(self.supported_versions):
                            self.vmbus_connect(version)
                        self.current_message = 0
                        self.fuzzing = True
                        self.vmbus_test1_run()
                        self.fuzzing = False
                    m += 1
        except KeyboardInterrupt:
            print '***** Control-C *****'
        except Exception, error:
            traceback.print_exc()
        finally:
            self.vmbus_rescind_all_offers()
        return ModuleResult.PASSED
