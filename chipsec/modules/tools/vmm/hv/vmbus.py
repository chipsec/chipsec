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
Hyper-V VMBus functionality
"""
import os
import sys
import time
import chipsec_util
from struct import *
from random import *
from chipsec.modules.tools.vmm.common import *
from chipsec.modules.tools.vmm.hv.define import *
from chipsec.library.logger import *
from chipsec.library.file import *
from chipsec.module_common import *
from chipsec.hal.vmm import VMM
from chipsec.library.defines import *


class RingBuffer(BaseModuleDebug):
    def __init__(self):
        BaseModuleDebug.__init__(self)
        self.promt = 'RING BUFFER'
        self.signal = True
        self.send_size = 0
        self.base_addr = []
        self.pfn = []

    def __del__(self):
        BaseModuleDebug.__del__(self)
        self.dbg('Free kernel memory (pfn pages)')
        self.base_addr = []
        self.send_size = 0
        self.pfn = []

    ##
    # ringbuffer_alloc - allocates kernel memory for ring buffer
    ##
    def ringbuffer_alloc(self, pages=4):
        (va, pa) = self.cs.mem.alloc_physical_mem(pages << 12, 0xFFFFFFFFFFFFFFFF)
        self.base_addr.append(va)
        if pa != 0:
            for i in range(pages):
                self.pfn.append(pa + (i << 12))
            self.ringbuffer_init()
        self.send_size = pages >> 1
        return pa != 0

    ##
    # ringbuffer_init - init data and control structures in the ring buffer
    ##
    def ringbuffer_init(self):
        init_page = '\x00' * 0x1000
        for addr in self.pfn:
            self.cs.mem.write_physical_mem(addr, len(init_page), init_page)
        return

    ##
    # ringbuffer_copyfrom - routine to copy to source from ring buffer
    ##
    def ringbuffer_copyfrom(self, index, total):
        ring_data_page = self.send_size + 1
        ring_data_size = len(self.pfn) - self.send_size - 1
        data = ''
        while total > 0:
            page = ring_data_page + (index >> 12) % ring_data_size
            addr = self.pfn[page] + (index & 0xFFF)
            size = min(total, 0x1000 - (index & 0xFFF))
            data += self.cs.mem.read_physical_mem(addr, size)
            total -= size
            index += size
        return data

    ##
    # ringbuffer_copyto - routine to copy from source to ring buffer
    ##
    def ringbuffer_copyto(self, index, data):
        ring_data_page = 1
        ring_data_size = self.send_size - 1
        while data:
            page = ring_data_page + (index >> 12) % ring_data_size
            addr = self.pfn[page] + (index & 0xFFF)
            size = min(len(data), 0x1000 - (index & 0xFFF))
            self.cs.mem.write_physical_mem(addr, size, data[:size])
            data = data[size:]
            index += size
        return

    ##
    # ringbuffer_read - Read and advance the read index
    ##
    def ringbuffer_read(self):
        ring_data_size = (len(self.pfn) - self.send_size - 1) << 12
        buffer = self.cs.mem.read_physical_mem(self.pfn[self.send_size], 0x10)
        write_index, read_index, _, _ = unpack('<4L', buffer)
        delta = write_index - read_index
        avail = delta if delta >= 0 else ring_data_size + delta
        if avail == 0:
            return ''
        header = self.ringbuffer_copyfrom(read_index, 16)
        pksize = 8 * unpack('<4HQ', header)[2] + 8
        buffer = self.ringbuffer_copyfrom(read_index, pksize)
        read_index = (read_index + pksize) % ring_data_size
        self.cs.mem.write_physical_mem(self.pfn[self.send_size] + 4, 4, DD(read_index))
        return buffer[:pksize - 8]

    ##
    # ringbuffer_write - Write to the ring buffer
    ##
    def ringbuffer_write(self, data):
        ring_data_size = (self.send_size - 1) << 12
        buffer = self.cs.mem.read_physical_mem(self.pfn[0], 0x10)
        write_index, read_index, _, _ = unpack('<4L', buffer)
        delta = read_index - write_index
        avail = delta if delta > 0 else ring_data_size + delta
        data += DD(0) + DD(write_index)
        if avail < len(data):
            return False
        self.ringbuffer_copyto(write_index, data)
        write_index = (write_index + len(data)) % ring_data_size
        self.cs.mem.write_physical_mem(self.pfn[0] + 0, 4, DD(write_index))
        self.signal = True
        return True

    def ringbuffer_read_with_timeout(self, timeout=0):
        self.dbg('Read and advance the read index ...')
        start_time = time.time()
        polling = True
        while polling:
            message = self.ringbuffer_read()
            polling = ((timeout == 0) or (time.time() - start_time <= timeout)) and not message
        return message

    def ringbuffer_write_with_timeout(self, message, timeout=0):
        self.dbg('Write to the ring buffer ...')
        start_time = time.time()
        polling = True
        while polling:
            result = self.ringbuffer_write(message)
            polling = ((timeout == 0) or (time.time() - start_time <= timeout)) and not result
        return result


class HyperV(BaseModuleDebug):
    def __init__(self):
        BaseModuleDebug.__init__(self)
        self.hypercall = VMM(self.cs)
        self.hypercall.init()
        self.membuf = self.cs.mem.alloc_physical_mem(4 * 0x1000, 0xFFFFFFFF)
        self.cs.mem.write_physical_mem(self.membuf[1], 4 * 0x1000, b'\x00' * 4 * 0x1000)
        self.old_sint2 = []
        self.old_simp = []
        self.old_siefp = []
        self.simp = []
        self.siefp = []

    def __del__(self):
        BaseModuleDebug.__del__(self)
        self.dbg('Free kernel memory')
        # if self.membuf[0] != 0:
        #    self.cs.mem.free_physical_mem(self.membuf[0])
        if len(self.old_sint2) == 2:
            self.cs.msr.write_msr(0, HV_X64_MSR_SINT2, self.old_sint2[0], self.old_sint2[1])
        if len(self.old_simp) == 2:
            self.cs.msr.write_msr(0, HV_X64_MSR_SIMP, self.old_simp[0], self.old_simp[1])
        if len(self.old_siefp) == 2:
            self.cs.msr.write_msr(0, HV_X64_MSR_SIEFP, self.old_siefp[0], self.old_siefp[1])
        for i in [x for x in self.ringbuffers]:
            del self.ringbuffers[i]

    ##
    # hv_init
    ##
    def hv_init(self):
        self.old_sint2 = self.cs.msr.read_msr(0, HV_X64_MSR_SINT2)
        self.old_simp = self.cs.msr.read_msr(0, HV_X64_MSR_SIMP)
        self.old_siefp = self.cs.msr.read_msr(0, HV_X64_MSR_SIEFP)
        pa = self.membuf[1]
        self.sint3 = self.cs.msr.read_msr(0, HV_X64_MSR_SINT3)
        self.cs.msr.write_msr(0, HV_X64_MSR_SINT2, self.sint3[0], self.sint3[1])
        self.cs.msr.write_msr(0, HV_X64_MSR_SIEFP, (pa & 0xFFFFFFFF) | 0x1, pa >> 32)
        #self.cs.msr.write_msr(0, HV_X64_MSR_SCONTROL, 0x1, 0x0)
        self.simp = self.cs.msr.read_msr(0, HV_X64_MSR_SIMP)
        self.siefp = self.cs.msr.read_msr(0, HV_X64_MSR_SIEFP)
        self.simp = (self.simp[0] + (self.simp[1] << 32)) & 0xFFFFFFFFFFFFF000
        self.siefp = (self.siefp[0] + (self.siefp[1] << 32)) & 0xFFFFFFFFFFFFF000
        return

    ##
    # hv_post_msg - Send a message
    ##
    def hv_post_msg(self, message):
        retries = 3
        hciv = hv_hciv(0, 0, HV_POST_MESSAGE)
        while retries > 0:
            result = self.hypercall.hypercall64_memory_based(hciv, message[:0x100]) & 0xFFFF
            if result == HV_STATUS_INSUFFICIENT_BUFFERS:
                retries -= 1
                time.sleep(0.1)
            else:
                retries = 0
        return result

    ##
    # hv_recv_msg - recieve message if exist otherwise empty string
    ##
    def hv_recv_msg(self, sint):
        buffer = self.cs.mem.read_physical_mem(self.simp + 0x100 * sint, 0x100)
        message_type, payload_size, message_flags = unpack('<LBB', buffer[0:6])
        if message_type == HVMSG_NONE:
            buffer = ''
        else:
            self.cs.mem.write_physical_mem(self.simp + 0x100 * sint, 0x4, DD(HVMSG_NONE))
            if message_flags & 0x1:
                self.cs.msr.write_msr(0, HV_X64_MSR_EOM, 0x0, 0x0)
        return buffer

    ##
    # hv_signal_event - send an event notification
    ##
    def hv_signal_event(self, connection_id, flag_number):
        hciv = hv_hciv(0, 0, HV_SIGNAL_EVENT)
        buffer = pack('<LHH', connection_id, flag_number, 0x0)
        result = self.hypercall.hypercall64_memory_based(hciv, buffer) & 0xFFFF
        return result

    ##
    # hv_recv_events - recieve all current events
    ##
    def hv_recv_events(self, sint):
        events = set()
        buffer = self.cs.mem.read_physical_mem(self.siefp + 0x100 * sint, 0x100)
        buffer = unpack('<64L', buffer)
        for i in range(64):
            if buffer[i]:
                for n in range(32):
                    if (buffer[i] >> n) & 0x1:
                        events.add(i * 32 + n)
        return events


class VMBus(HyperV):
    def __init__(self):
        HyperV.__init__(self)
        self.promt = 'VMBUS'
        self.onmessage_timeout = 0.1  # 0.02
        self.int_page = self.membuf[1] + 1 * 0x1000
        self.monitor_page1 = self.membuf[1] + 2 * 0x1000
        self.monitor_page2 = self.membuf[1] + 3 * 0x1000
        self.recv_int_page = self.int_page + 0x000
        self.send_int_page = self.int_page + 0x800
        self.supported_versions = {}
        self.offer_channels = {}
        self.open_channels = {}
        self.created_gpadl = {}
        self.ringbuffers = {}
        self.next_gpadl = 0x200E1E10

    ##
    # vmbus_init
    ##
    def vmbus_init(self):
        self.hv_init()
        self.vmbus_clear()
        return

    ##
    # vmbus_clear
    ##
    def vmbus_clear(self):
        # Purge hypervisor message queue
        while self.vmbus_recv_msg(0.1):
            pass
        return

    ##
    # vmbus_get_next_gpadl
    ##
    def vmbus_get_next_gpadl(self):
        self.next_gpadl += 1
        return self.next_gpadl

    ##
    # vmbus_post_msg - send a msg on the vmbus's message connection
    ##
    def vmbus_post_msg(self, message):
        if len(message) > 240:
            self.err(f'vmbus_post_msg: message it too long {len(message):d} bytes')
            message = message[:240]
        header = pack('<4L', VMBUS_MESSAGE_CONNECTION_ID, 0x0, 0x1, len(message))
        result = self.hv_post_msg(header + message)
        if result != HV_STATUS_SUCCESS:
            status = hypercall_status_codes[result] if result in hypercall_status_codes else ''
            self.err(f'vmbus_post_msg returns  {result:02X} {status}')
        return result == HV_STATUS_SUCCESS

    ##
    # vmbus_recv_msg - recieve message. it may return empty string in case of timeout
    ##
    def vmbus_recv_msg(self, timeout=0):
        start_time = time.time()
        polling = True
        while polling:
            message = self.hv_recv_msg(VMBUS_MESSAGE_SINT)
            polling = ((timeout == 0) or (time.time() - start_time <= timeout)) and not message
        if message:
            msg_type, payload_size, msg_flags, rsvd, port_id = unpack('<LBBHQ', message[0:16])
            if msg_type not in [HVMSG_NONE, 0x0001]:
                status = hv_message_type[msg_type] if msg_type in hv_message_type else ''
                self.fatal(f'vmbus_recv_msg: unhandeled message type 0x{msg_type:08X} {status}')
            if (payload_size < 8) or (payload_size > 240):
                self.msg(f'vmbus_recv_msg: invalid payload size {payload_size:d}')
                payload_size = 240
            if rsvd != 0x0000:
                self.msg(f'vmbus_recv_msg: invalid reserved field 0x{rsvd:04X}')
            # if port_id != VMBUS_MESSAGE_PORT_ID:
            #    self.msg('vmbus_recv_msg: invalid ConnectionID 0x%016x' % port_id)
            message = message[16: 16 + payload_size]
        return message

    ##
    # vmbus_setevent - Trigger an event notification on the specified channel
    ##
    def vmbus_setevent(self, child_relid):
        self.dbg('Trigger an event notification on the specified channel ...')
        if child_relid not in self.open_channels:
            self.err(f'vmbus_setevent could not find channel with child relid: {child_relid:d}')
            return False
        channel = self.open_channels[child_relid]['offer']
        if channel['monitor_allocated'] == 1:
            monitor_bit = channel['monitor_id'] & 0x1F
            monitor_grp = channel['monitor_id'] >> 5
            trigger_group_offset = 8 + 8 * monitor_grp
            self.cs.mem.set_mem_bit(self.send_int_page, child_relid)
            self.cs.mem.set_mem_bit(self.monitor_page2 + trigger_group_offset, monitor_bit)
        else:
            # Send an event notification to the parent
            self.dbg('Send an event notification to the parent ...')
            self.cs.mem.set_mem_bit(self.send_int_page, child_relid)
            result = self.hv_signal_event(channel['connection_id'], 0x0)
            if result != 0:
                status = hypercall_status_codes[result] if result in hypercall_status_codes else ''
                self.err(f'vmbus_setevent returns  {result:02X} {status}')
                return False
        return True

    ##
    # vmbus_recv_events - recieve all current events
    ##
    def vmbus_recv_events(self):
        return self.hv_recv_events(VMBUS_MESSAGE_SINT)

    ##
    # vmbus_get_next_version - returns the next version
    ##
    def vmbus_get_next_version(self, current_version):
        versions = {VERSION_WIN8_1: VERSION_WIN8, VERSION_WIN8: VERSION_WIN7, VERSION_WS2008: VERSION_INVAL}
        return versions[current_version] if current_version in versions else VERSION_INVAL

    ##
    # vmbus_connect - Sends a connect request on the partition service connection
    ##
    def vmbus_connect(self, vmbus_version=VERSION_WIN8, target_vcpu=0x0):
        self.dbg('Sending channel initiate msg ...')
        channel_message_header = pack('<LL', CHANNELMSG_INITIATE_CONTACT, 0x0)
        channel_initiate_contact = pack('<LLQQQ', vmbus_version, target_vcpu, self.int_page, self.monitor_page1, self.monitor_page2)
        result = self.vmbus_post_msg(channel_message_header + channel_initiate_contact)
        if result:
            result = self.vmbus_onmessage() == CHANNELMSG_VERSION_RESPONSE
        return result

    ##
    # vmbus_establish_gpadl - Estabish a GPADL for the specified buffer
    ##
    def vmbus_establish_gpadl(self, child_relid, gpadl, pfn):
        self.dbg('Estabish a GPADL for the specified buffer ...')
        byte_offset = 0
        byte_count = len(pfn) << 12
        pfn_array = ''.join([DQ(addr >> 12) for addr in pfn])
        gpa_range = pack('<LL', byte_count, byte_offset) + pfn_array
        rangecount = 0x1
        range_buflen = len(gpa_range)
        channel_message_header = pack('<LL', CHANNELMSG_GPADL_HEADER, 0x0)
        channel_gpadl_header = pack('<LLHH', child_relid, gpadl, range_buflen, rangecount)
        result = self.vmbus_post_msg(channel_message_header + channel_gpadl_header + gpa_range[:27 * 8])
        gpa_range = gpa_range[27 * 8:]
        while result and gpa_range != '':
            channel_message_header = pack('<LL', CHANNELMSG_GPADL_BODY, 0x0)
            channel_gpadl_body = pack('<LL', 0x0, gpadl)
            result = self.vmbus_post_msg(channel_message_header + channel_gpadl_body + gpa_range[:28 * 8])
            gpa_range = gpa_range[28 * 8:]
        if result:
            result = self.vmbus_onmessage() == CHANNELMSG_GPADL_CREATED
        return result

    ##
    # vmbus_teardown_gpadl - Teardown the specified GPADL handle
    ##
    def vmbus_teardown_gpadl(self, child_relid, gpadl):
        self.dbg('Teardown the specified GPADL handle ...')
        channel_message_header = pack('<LL', CHANNELMSG_GPADL_TEARDOWN, 0x0)
        channel_gpadl_teardown = pack('<LL', child_relid, gpadl)
        result = self.vmbus_post_msg(channel_message_header + channel_gpadl_teardown)
        if result:
            msgtype = self.vmbus_onmessage()
            if msgtype == CHANNELMSG_RESCIND_CHANNELOFFER:
                self.vmbus_process_rescind_offer(child_relid)
                result = result and (self.vmbus_onmessage() == CHANNELMSG_GPADL_TORNDOWN)
                result = result and (self.vmbus_onmessage() == CHANNELMSG_OFFERCHANNEL)
            else:
                result = (msgtype == CHANNELMSG_GPADL_TORNDOWN)

        return result

    ##
    # vmbus_open - Open the specified channel
    ##
    def vmbus_open(self, child_relid, gpadl, pageoffset=2, userdata='\x00' * 120):
        self.dbg('Open the specified channel ...')
        openid = child_relid
        target_vp = 0x0
        channel_message_header = pack('<LL', CHANNELMSG_OPENCHANNEL, 0x0)
        channel_open_channel = pack('<5L', child_relid, openid, gpadl, target_vp, pageoffset)
        result = self.vmbus_post_msg(channel_message_header + channel_open_channel + userdata)
        if result:
            result = self.vmbus_onmessage() == CHANNELMSG_OPENCHANNEL_RESULT
        return result

    ##
    # vmbus_close - Close the specified channel
    ##
    def vmbus_close(self, child_relid):
        self.dbg('Close the specified channel ...')
        channel_message_header = pack('<LL', CHANNELMSG_CLOSECHANNEL, 0x0)
        channel_close_channel = pack('<L', child_relid)
        return self.vmbus_post_msg(channel_message_header + channel_close_channel)

    ##
    # vmbus_disconnect - Sends a disconnect request on the partition service connection
    ##
    def vmbus_disconnect(self):
        self.dbg('Sending a disconnect request ...')
        channel_message_header = pack('<LL', CHANNELMSG_UNLOAD, 0x0)
        result = self.vmbus_post_msg(channel_message_header)
        result = result and (self.vmbus_onmessage() == 17)
        return result

    ##
    # vmbus_request_offers - Send a request to get all our pending offers
    ##
    def vmbus_request_offers(self):
        self.dbg('Sending a request to get all our pending offers ...')
        channel_message_header = pack('<LL', CHANNELMSG_REQUESTOFFERS, 0x0)
        result = self.vmbus_post_msg(channel_message_header)
        while result:
            msgtype = self.vmbus_onmessage()
            if msgtype != CHANNELMSG_OFFERCHANNEL:
                break
        return result and (msgtype == CHANNELMSG_ALLOFFERS_DELIVERED)

    ##
    # vmbus_process_rescind_offer - Rescind the offer by initiating a device removal
    ##
    def vmbus_process_rescind_offer(self, child_relid):
        self.dbg('Rescind the offer by initiating a device removal ...')
        channel_message_header = pack('<LL', CHANNELMSG_RELID_RELEASED, 0x0)
        channel_relid_released = pack('<L', child_relid)
        return self.vmbus_post_msg(channel_message_header + channel_relid_released)

    ##
    # vmbus_onmessage - Handler for channel protocol messages.
    ##
    def vmbus_onmessage(self):
        msgtype = CHANNELMSG_INVALID

        channelmsg = {
            CHANNELMSG_OFFERCHANNEL: 188,
            CHANNELMSG_ALLOFFERS_DELIVERED: 0,
            CHANNELMSG_GPADL_CREATED: 12,
            CHANNELMSG_OPENCHANNEL_RESULT: 12,
            CHANNELMSG_GPADL_TORNDOWN: 4,
            CHANNELMSG_RESCIND_CHANNELOFFER: 4,
            CHANNELMSG_VERSION_RESPONSE: 8
        }

        message = self.vmbus_recv_msg(self.onmessage_timeout)

        if len(message) == 0:
            self.msg('vmbus_onmessage: timeout')
        elif len(message) >= 8:
            msgtype, padding = unpack('<LL', message[:8])
            message_body = message[8:]

            self.dbg(f'vmbus_onmessage: message {msgtype:d} {vmbus_channel_message_type[msgtype]}')

            if msgtype not in channelmsg:
                self.msg(f'vmbus_onmessage: invalid message type {msgtype:d}')
                self.hex('Message', message)
            elif channelmsg[msgtype] > len(message_body):
                self.msg('vmbus_onmessage: message is too short!')
                self.hex('Message', message)
                exit(1)

            if padding != 0x00000000:
                self.msg(f'vmbus_onmessage invalid padding {padding:d}')

        # vmbus_ongpadl_created - GPADL created handler
        if msgtype == CHANNELMSG_GPADL_CREATED:
            child_relid, gpadl, status = unpack('<3L', message_body[:12])
            self.created_gpadl[gpadl] = {'child_relid': child_relid, 'status': status}
        # vmbus_onopen_result - Open result handler
        elif msgtype == CHANNELMSG_OPENCHANNEL_RESULT:
            child_relid, openid, status = unpack('<3L', message_body[:12])
            self.open_channels[child_relid] = {'openid': openid, 'status': status}
            offer = 'none'
            for i in self.offer_channels.keys():
                if self.offer_channels[i]['child_relid'] == child_relid:
                    offer = self.offer_channels[i]
                    break
            self.open_channels[child_relid]['offer'] = offer
        # vmbus_onversion_response - Version response handler
        elif msgtype == CHANNELMSG_VERSION_RESPONSE:
            version_supported, version = unpack('<2L', message_body[:8])
            if version_supported != 0x00:
                self.supported_versions[version] = 0x1
        # vmbus_onoffer - Handler for channel offers from vmbus in parent partition.
        elif msgtype == CHANNELMSG_OFFERCHANNEL:
            offer = message_body
            channel = {}
            uuid1 = uuid(offer[0x00:0x10])
            uuid2 = uuid(offer[0x10:0x20])
            # struct vmbus_channel_offer
            guid1 = hv_guid_desc[uuid1] if uuid1 in hv_guid_desc else 'Unknown'
            channel['name'] = guid1
            channel['flags'] = unpack('<H', offer[0x30: 0x32])[0]
            channel['mmio'] = unpack('<H', offer[0x32: 0x34])[0]
            channel['userdef'] = offer[0x34: 0xAC]
            channel['sub_channel'] = unpack('<H', offer[0xAC: 0xAE])[0]
            # struct vmbus_channel_offer_channel (continue)
            channel['child_relid'] = unpack('<L', offer[0xB0: 0xB4])[0]
            channel['monitor_id'] = unpack('<B', offer[0xB4: 0xB5])[0]
            channel['monitor_allocated'] = unpack('<B', offer[0xB5: 0xB6])[0] & 0x1
            channel['dedicated_interrupt'] = unpack('<H', offer[0xB6: 0xB8])[0] & 0x1
            channel['connection_id'] = unpack('<L', offer[0xB8: 0xBC])[0]
            self.offer_channels[offer[0x00:0x20]] = channel

        return msgtype

    ##
    # vmbus_recvpacket - Retrieve the user packet on the specified channel
    ##
    def vmbus_recvpacket(self, child_relid):
        self.dbg('Retrieve the user packet on the specified channel ...')
        rb = self.ringbuffers[child_relid]
        buffer = rb.ringbuffer_read_with_timeout(self.onmessage_timeout)
        if len(buffer) >= 16:
            packet_type, offset8, len8, flags, requestid = unpack('<4HQ', buffer[:16])
            buffer = buffer[16:]
        return buffer

    ##
    # vmbus_sendpacket - Send the specified buffer on the given channel
    ##
    def vmbus_sendpacket(self, child_relid, data, requestid, packet_type, flags):
        self.dbg('Send the specified buffer on the given channel ...')
        rb = self.ringbuffers[child_relid]
        while (len(data) & 0x7) != 0:
            data += '\x00'
        offset8 = 16 >> 3
        len8 = offset8 + (len(data) >> 3)
        vmpacket_descriptor = pack('<4HQ', packet_type, offset8, len8, flags, requestid)
        rb.ringbuffer_write(vmpacket_descriptor + data)
        if rb.signal:
            self.vmbus_setevent(child_relid)
        return

    ##
    # vmbus_sendpacket_pagebuffer - Send a range of single-page buffer
    ##
    def vmbus_sendpacket_pagebuffer(self):
        self.dbg('Send a range of single-page buffer ...')
        return

    ##
    # vmbus_sendpacket_multipagebuffer - Send a multi-page buffer packet
    ##
    def vmbus_sendpacket_multipagebuffer(self):
        self.dbg('Send a multi-page buffer packet ...')
        return

    ##
    # vmbus_recvpacket_raw - Retrieve the raw packet on the specified channel
    ##
    def vmbus_recvpacket_raw(self):
        self.dbg('Retrieve the raw packet on the specified channel ...')
        return


class VMBusDiscovery(VMBus):
    def __init__(self):
        VMBus.__init__(self)

    def __del__(self):
        VMBus.__del__(self)

    ##
    # vmbus_rescind_all_offers - Rescind all offers by initiating a device removal
    ##
    def vmbus_rescind_all_offers(self):
        # for i in self.offer_channels.keys():
        #    relid = self.offer_channels[i]['child_relid']
        #    self.vmbus_process_rescind_offer(relid)
        for i in range(0x10):
            self.vmbus_process_rescind_offer(i)
        return

    ##
    # get_relid_by_guid
    ##
    def get_relid_by_guid(self, guid):
        relid = 0
        for i in self.offer_channels.keys():
            if (guid == uuid(i[0x00:0x10])) or (guid == uuid(i[0x10:0x20])):
                relid = self.offer_channels[i]['child_relid']
                break
        return relid

    ##
    # scan_supported_versions
    ##
    def scan_supported_versions(self, mask=0x000F000F):
        version = 0x00000000
        while True:
            self.vmbus_connect(version)
            if version == mask:
                break
            version = (~(~version & mask) + 1) & mask
        return

    ##
    # scan_physical_addresses
    ##
    def scan_physical_addresses(self, version):
        pages = (self.int_page, self.monitor_page1, self.monitor_page2)
        FFs = 0xFFFFFFFFFFFFFFFF
        for i in range(64):
            self.supported_versions = {}
            self.int_page = (FFs << (63 - i)) & FFs
            self.dbg(f'Address: 0x{self.int_page:016X}')
            self.vmbus_connect(version)
            print(self.supported_versions)
        (self.int_page, self.monitor_page1, self.monitor_page2) = pages
        return

    ##
    # print_supported_versions
    ##
    def print_supported_versions(self):
        self.msg('')
        self.msg('******************** Supported versions ********************')
        for version in sorted(self.supported_versions.keys()):
            status = 'Unknown' if version not in vmbus_versions else vmbus_versions[version]
            self.msg(f'  {version >> 16:d} . {version & 0xFFFF:2d} - {status}')
        return

    ##
    # print_offer_channels - Print offered channels
    ##
    def print_offer_channels(self):
        self.msg('')
        self.msg('******************** Offered channels **********************')
        uuid_sorted_by_connid = dict((value['connection_id'], key) for (key, value) in self.offer_channels.items()).values()
        for i in uuid_sorted_by_connid:
            channel = self.offer_channels[i]
            flags = []
            for n in range(16):
                if (n in channel_flags) and (((channel['flags'] >> n) & 0x1) == 0x1):
                    flags.append(channel_flags[n])

            conid = f'Connection ID: 0x{channel["connection_id"]:08X}'
            relid = f'Child relid: 0x{channel["child_relid"]:08X}'
            mmios = f'MMIO: {channel["mmio"]:d}MB'
            subch = f'Sub channel: 0x{channel["sub_channel"]:04X}'
            monid = f'Monitor: {channel["monitor_allocated"]:d} ID=0x{channel["monitor_id"]:02X}'
            dintr = f'Dedicated interrupt: {channel["dedicated_interrupt"]:d}'
            flags = f'Flags: 0x{channel["flags"]:04X} >{", ".join(flags)}'

            self.msg('')
            self.msg(f'{channel["name"]}')
            self.msg(f'  Hardware IDs:  {uuid(i[0x00:0x10])}   {uuid(i[0x10:0x20])}')
            self.msg(f'  {conid}   {relid}   {subch}   {monid}')
            self.msg(f'  {mmios}   {dintr}   {flags}')
        return

    ##
    # print_created_gpadl
    ##
    def print_created_gpadl(self):
        self.msg('')
        self.msg('******************** Created GPADLs ************************')
        self.msg('  gpadl        |  child_relid  |  creation_status  ')
        self.msg('---------------------------------------------------')
        for gpadl in sorted(self.created_gpadl.keys()):
            channel = self.created_gpadl[gpadl]
            self.msg(f'  0x{gpadl:08X}   |  0x{channel["child_relid"]:08X}   |  0x{channel["status"]:08X}')
        self.msg('---------------------------------------------------')
        return

    ##
    # print_open_channels
    ##
    def print_open_channels(self):
        self.msg('')
        self.msg('******************** Open Channels *************************')
        self.msg('  child_relid  |  openid       |  status           ')
        self.msg('---------------------------------------------------')
        for child_relid in sorted(self.open_channels):
            channel = self.open_channels[child_relid]
            self.msg(f'  0x{child_relid:08X}   |  0x{channel["openid"]:08X}   |  0x{channel["status"]:08X}')
        self.msg('---------------------------------------------------')
        return

    ##
    # print_events
    ##
    def print_events(self):
        events = self.vmbus_recv_events()
        result = []
        for i in events:
            result.append(f'{i:02X}')
        if len(result) != 0:
            self.msg('EVENTS: ' + ', '.join(result))
        return
