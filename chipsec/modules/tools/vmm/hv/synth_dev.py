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
Hyper-V VMBus synthetic device generic fuzzer

Usage:

  Print channel offers:

  ``chipsec_main.py -i -m tools.vmm.hv.synth_dev -a info``

  Fuzzing device with specified relid:

  ``chipsec_main.py -i -m tools.vmm.hv.synth_dev -a fuzz,<relid> -l log.txt``

Note: the fuzzer is incompatible with native VMBus driver (``vmbus.sys``). To use it, remove ``vmbus.sys``
"""
import sys
import traceback
from struct import pack
from chipsec.library.returncode import ModuleResult
from chipsec.module_common import BaseModule
from chipsec.modules.tools.vmm.common import session_logger, get_int_arg
from chipsec.modules.tools.vmm.hv.define import VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED, vm_pkt
from chipsec.modules.tools.vmm.hv.vmbus import RingBuffer, VMBusDiscovery

sys.stdout = session_logger(True, 'synth_dev')


class VMBusDeviceFuzzer(VMBusDiscovery):
    def __init__(self):
        VMBusDiscovery.__init__(self)
        self.responses = {}

    def send_1(self, relid, messages, info, order):
        if len(messages) > 0:
            msg_sent = messages.pop(0)
            vmpkt_datainband = list(vm_pkt.keys())[list(vm_pkt.values()).index('VM_PKT_DATA_INBAND')]
            self.vmbus_sendpacket(relid, msg_sent, 0x0, vmpkt_datainband, VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED)
            msg_recv = self.vmbus_recvpacket(relid)
            if msg_recv != '':
                (msg1, msg2) = (msg_recv, msg_sent) if order else (msg_sent, msg_recv)
                if msg1 not in info:
                    info[msg1] = {'next': {}, 'count': 0, 'message': ''}
                info[msg1]['count'] += 1
                info[msg1]['message'] = msg2
                info[msg1]['next'] = self.send_1(relid, messages, info[msg1]['next'], order)
        return info

    def device_fuzzing(self, relid):
        for x in range(1, 0x100):
            for a in range(0, 0x100):
                self.ringbuffers[relid].ringbuffer_init()
                self.vmbus_establish_gpadl(relid, self.ringbuffers[relid].gpadl, self.ringbuffers[relid].pfn)
                self.vmbus_open(relid, self.ringbuffers[relid].gpadl, self.ringbuffers[relid].send_size)
                msg = pack('<LL', x, ((a & 0xf0) << 12) | (a % 0x0f))
                try:
                    self.responses = self.send_1(relid, [msg], self.responses, True)
                finally:
                    self.vmbus_close(relid)
                    self.vmbus_teardown_gpadl(relid, self.ringbuffers[relid].gpadl)
        return

    def print_1(self, info, indent=0):
        if len(info) == 0:
            return
        for i in self.responses:
            self.msg(f'{"  " * indent}{i.hex():20}:{info[i]["message"].hex():20}  {info[i]["count"]:4d}')
            self.print_1(info[i]['next'], indent + 1)
        return

    def print_statistics(self):
        self.msg('Response statistics:')
        self.print_1(self.responses)
        return


class synth_dev(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)

    def usage(self):
        print('  Usage:')
        print('    chipsec_main.py -i -m tools.vmm.hv.synth_dev -a info')
        print('      print channel offers')
        print('    chipsec_main.py -i -m tools.vmm.hv.synth_dev -a fuzz,<relid>')
        print('      fuzzing device with specified relid')
        print('  Note: the fuzzer is incompatible with native VMBus driver (vmbus.sys). To use it, remove vmbus.sys')
        return

    def run(self, module_argv):
        self.logger.start_test("Hyper-V VMBus synthetic device fuzzer")

        command = module_argv[0] if len(module_argv) > 0 and module_argv[0] != '' else 'none'
        relid = get_int_arg(module_argv[1]) if len(module_argv) > 1 and module_argv[1] != '' else 0x5

        vb = VMBusDeviceFuzzer()
        vb.debug = False
        vb.vmbus_init()
        try:
            vb.vmbus_connect()
            vb.vmbus_request_offers()

            if relid not in [value['child_relid'] for value in vb.offer_channels.values()]:
                vb.fatal(f'child relid #{relid:d} has not been found!')

            vb.ringbuffers[relid] = RingBuffer()
            vb.ringbuffers[relid].debug = False
            vb.ringbuffers[relid].ringbuffer_alloc(4)
            vb.ringbuffers[relid].gpadl = vb.vmbus_get_next_gpadl()

            if command == 'info':
                vb.vmbus_establish_gpadl(relid, vb.ringbuffers[relid].gpadl, vb.ringbuffers[relid].pfn)
                vb.vmbus_open(relid, vb.ringbuffers[relid].gpadl, vb.ringbuffers[relid].send_size)
                vb.print_offer_channels()
                vb.print_created_gpadl()
                vb.print_open_channels()
                vb.vmbus_close(relid)
                vb.vmbus_teardown_gpadl(relid, vb.ringbuffers[relid].gpadl)
            elif command == 'fuzz':
                vb.promt = f'DEVICE {relid:02d}'
                vb.msg('Fuzzing VMBus devices ...')
                vb.device_fuzzing(relid)
                vb.print_statistics()
            else:
                self.usage()

        except KeyboardInterrupt:
            print('***** Control-C *****')
        except Exception:
            print('\n\n')
            traceback.print_exc()
            print('\n\n')
        finally:
            vb.vmbus_rescind_all_offers()
            del vb
        self.result.setStatusBit(self.result.status.SUCCESS)
        return self.result.getReturnCode(ModuleResult.PASSED)
