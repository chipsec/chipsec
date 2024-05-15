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
Hyper-V VMBus synthetic keyboard fuzzer. Fuzzes inbound ring buffer in VMBus virtual keyboard device.

Usage:
  ``chipsec_main.py -i -m tools.vmm.hv.synth_kbd -a fuzz -l log.txt``

Note: the fuzzer is incompatible with native VMBus driver (``vmbus.sys``). To use it, remove ``vmbus.sys``
"""
import sys
import traceback
from random import randint
from struct import pack, unpack
from chipsec.library.defines import DD
from chipsec.library.returncode import ModuleResult
from chipsec.module_common import BaseModule
from chipsec.modules.tools.vmm.common import overwrite, session_logger
from chipsec.modules.tools.vmm.hv.define import HV_KBD_GUID, VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED, vm_pkt
from chipsec.modules.tools.vmm.hv.vmbus import RingBuffer, VMBusDiscovery

SYNTH_KBD_VERSION = 0x00010000
SYNTH_KBD_PROTOCOL_REQUEST = 1
SYNTH_KBD_PROTOCOL_RESPONSE = 2
SYNTH_KBD_EVENT = 3
SYNTH_KBD_LED_INDICATORS = 4

sys.stdout = session_logger(True, 'synth_kbd')


class RingBufferFuzzer(RingBuffer):
    def __init__(self):
        RingBuffer.__init__(self)
        self.fuzzing = False
        self.count = 0

    ##
    # ringbuffer_read - Fuzzing recv ring buffer pointers
    ##
    def ringbuffer_read(self):
        if self.fuzzing:
            buffer = self.cs.mem.read_physical_mem(self.pfn[self.send_size], 0x10)
            write_index, read_index, interrupt_mask, pending_send_sz = unpack('<4L', buffer)
            overwrite(buffer, DD(randint(0, 0xFFFFFFFF)), 4 * randint(0, 3))
            self.cs.mem.write_physical_mem(self.pfn[self.send_size], len(buffer), buffer)
            result = ''
            self.count += 1
            if self.count > 1000000:
                raise Exception
        else:
            result = RingBuffer.ringbuffer_read(self)
        return result


class synth_kbd(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)

    def usage(self):
        print('  Usage:')
        print('    chipsec_main.py -i -m tools.vmm.hv.synth_kbd -a fuzz')
        print('  Note: the fuzzer is incompatible with native VMBus driver (vmbus.sys). To use it, remove vmbus.sys')
        return

    def run(self, module_argv):
        self.logger.start_test("Hyper-V VMBus virtual keyboard fuzzer")

        if len(module_argv) > 0:
            command = module_argv[0]
        else:
            self.usage()
            self.result.setStatusBit(self.result.status.UNSUPPORTED_OPTION)
            return self.result.getReturnCode(ModuleResult.ERROR)

        vb = VMBusDiscovery()
        vb.debug = True
        vb.promt = 'VMBUS KBD'
        vb.vmbus_init()
        vb.vmbus_connect()
        vb.vmbus_request_offers()
        relid = vb.get_relid_by_guid(HV_KBD_GUID)
        if relid == 0:
            vb.fatal(f'Could not found keyboard device with GUID: {HV_KBD_GUID}')

        vb.ringbuffers[relid] = RingBufferFuzzer()
        vb.ringbuffers[relid].ringbuffer_alloc(4)
        vb.ringbuffers[relid].gpadl = vb.vmbus_get_next_gpadl()

        vb.vmbus_establish_gpadl(relid, vb.ringbuffers[relid].gpadl, vb.ringbuffers[relid].pfn)
        vb.vmbus_open(relid, vb.ringbuffers[relid].gpadl, vb.ringbuffers[relid].send_size)
        try:
            vb.print_offer_channels()
            vb.print_created_gpadl()
            vb.print_open_channels()

            synth_kbd_protocol_request = pack('<LL', SYNTH_KBD_PROTOCOL_REQUEST, SYNTH_KBD_VERSION)
            vmpkt_datainband = list(vm_pkt.keys())[list(vm_pkt.values()).index('VM_PKT_DATA_INBAND')]
            vb.vmbus_sendpacket(relid, synth_kbd_protocol_request, 0x0, vmpkt_datainband, VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED)
            synth_kbd_protocol_response = vb.vmbus_recvpacket(relid)
            if len(synth_kbd_protocol_response) != 8:
                vb.fatal('Invalid response from synthetic keyboard!')
            msg_type, proto_status = unpack('<LL', synth_kbd_protocol_response)
            if (proto_status & 0x1) == 0x1:
                vb.msg('synth_kbd protocol request has been accepted!')
                vb.ringbuffers[relid].debug = False
                vb.debug = False
                while True:
                    synth_kbd_msg = vb.vmbus_recvpacket(relid)
                    if not synth_kbd_msg:
                        continue
                    if len(synth_kbd_msg) < 12:
                        vb.hex('invalid message', synth_kbd_msg)
                        continue
                    msg_type, code, rsvd, info = unpack('<LHHL', synth_kbd_msg[:12])
                    if msg_type == SYNTH_KBD_EVENT:
                        vb.msg(f'keystroke: {code:04X}  flags: {info:08X}')
                        vb.ringbuffers[relid].fuzzing = (command == 'fuzzing')
                        if code == 0x0046:
                            vb.msg('*** Control Break ***')
                            vb.ringbuffers[relid].fuzzing = False
                            break
                    else:
                        vb.hex(f'unhandled message type: {msg_type:d}', synth_kbd_msg)
            else:
                vb.err('synth_kbd protocol request has failed!')

        except KeyboardInterrupt:
            print('***** Control-C *****')
        except Exception:
            print('\n\n')
            traceback.print_exc()
            print('\n\n')
        finally:
            vb.vmbus_close(relid)
            vb.vmbus_teardown_gpadl(relid, vb.ringbuffers[relid].gpadl)
            vb.vmbus_rescind_all_offers()
            del vb.ringbuffers[relid]
            del vb
        self.result.setStatusBit(self.result.status.SUCCESS)
        return self.result.getReturnCode(ModuleResult.PASSED)
