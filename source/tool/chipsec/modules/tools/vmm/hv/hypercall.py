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
Hyper-V specific hypercall functionality
"""

import os
import sys
import time
import binascii
import chipsec_util
from random                           import *
from struct                           import *
from define                           import *
from chipsec.modules.tools.vmm.common import *
from chipsec.logger                   import *
from chipsec.file                     import *
from chipsec.module_common            import *
from chipsec.hal.vmm                  import *

class HyperVHypercall(BaseModuleHwAccess):
    def __init__(self):
        BaseModuleHwAccess.__init__(self)
        self.hv = VMM(self.cs)
        self.hv.init()
        self.hypervisor_present = False
        self.hv_partitionid      = {}
        self.hv_connectionid     = {}
        self.hv_hypercalls       = {}
        self.param_matrix_status = {}

    ##
    ##  print_hypervisor_info
    ##
    def print_hypervisor_info(self):
        gprs = self.cpuid_info (0x00000001, 0x0, 'Feature Information')
        self.hypervisor_present = ((gprs[2] >> 31) & 0x1) == 0x1
        self.msg('ECX(31) - Hypervisor Present                  :  %x'   %  self.hypervisor_present)

        if self.hypervisor_present:

            gprs = self.cpuid_info (0x40000000, 0x0, 'Hypervisor CPUID leaf range and vendor ID signature')
            (max_input_value, id_signature_ebx, id_signature_ecx, id_signature_edx) = gprs
            id_signature = pack ('<3L', id_signature_ebx, id_signature_ecx, id_signature_edx ) 
            self.msg('The maximum input value for hypervisor CPUID  :  %08x' % max_input_value)
            self.msg('Hypervisor Vendor ID Signature                :  %s'   % id_signature)

            gprs = self.cpuid_info (0x40000001, 0x0, 'Hypervisor vendor-neutral interface identification')
            (interface_signature, rsvd_ebx, rsvd_ecx, rsvd_edx) = gprs
            interface_signature = pack ('<1L', interface_signature)
            self.msg('Hypervisor Interface Signature                :  %s' % interface_signature)

            if interface_signature == 'Hv#1':
                self.msg('INFO: HV hypervisor CPUID interface detected!')
                if (max_input_value < 0x40000005) or (max_input_value > 0x400000FF):
                    self.msg('')
                    self.msg('*** WARNING ***: Invalid CPUID.0x40000000.0x0.EAX value\n\n')

                for cpuid_eax in range (0x40000002, max_input_value):
                    self.print_hypervisor_cpuid(cpuid_eax)

        return

    ##
    ##  print_hypervisor_cpuid
    ##
    def print_hypervisor_cpuid(self, cpuid_eax, cpuid_ecx = 0x0):
        if cpuid_eax == 0x40000002:
            (eax, ebx, ecx, edx) = self.cpuid_info (cpuid_eax, cpuid_ecx, 'Hypervisor system identity')
            major_version   = 0xFFFF   & (ebx >> 16)
            minor_version   = 0xFFFF   & ebx
            service_branch  = 0xFF     & (edx >> 24)
            service_number  = 0xFFFFFF & edx
            self.msg('   EAX        - Build Number    :  %08x'   % eax            )
            self.msg('   EBX(31-16) - Major Version   :  %04x'   % major_version  )
            self.msg('   EBX(15-0)  - Minor Version   :  %04x'   % minor_version  )
            self.msg('   ECX        - Service Pack    :  %08x'   % ecx            )
            self.msg('   EDX(31-24) - Service Branch  :  %02x'   % service_branch )
            self.msg('   EDX(23-0)  - Service Number  :  %06x'   % service_number )
        elif cpuid_eax == 0x40000003:
            (eax, ebx, ecx, edx) = self.cpuid_info (cpuid_eax, cpuid_ecx, 'Feature identification')
            self.msg('   EAX - features available to the partition                :  %08x'   % eax)
            self.info_bitwise(eax, cpuid_desc[cpuid_eax]['EAX'])
            self.msg('   EBX - flags specified at partition creation              :  %08x'   % ebx)
            self.info_bitwise(ebx, cpuid_desc[cpuid_eax]['EBX'])
            self.msg('   ECX - power management related information               :  %08x'   % ecx)
            self.info_bitwise(ecx, cpuid_desc[cpuid_eax]['ECX'])
            self.msg('   EDX - misc. features available to the partition          :  %08x'   % edx)
            self.info_bitwise(edx, cpuid_desc[cpuid_eax]['EDX'])
        elif cpuid_eax == 0x40000004:
            (eax, ebx, ecx, edx) = self.cpuid_info (cpuid_eax, cpuid_ecx, 'Implementation recommendations')
            self.msg('   EAX(9-0) - recommendations for optimal performance       :  %08x'   % eax)
            self.msg('   EBX      - recommended number of attempts                :  %08x'   % ebx)
        elif cpuid_eax == 0x40000005:
            (eax, ebx, ecx, edx) = self.cpuid_info (cpuid_eax, cpuid_ecx, 'Implementation limits')
            self.msg('   EAX - The maximum number of virtual processors supported :  %08x'   % eax)
            self.msg('   EBX - The maximum number of logical processors supported :  %08x'   % ebx)
            self.msg('   ECX - The maximum number of physical interrupt vectors   :  %08x'   % ecx)
        elif cpuid_eax == 0x40000006:
            (eax, ebx, ecx, edx) = self.cpuid_info (cpuid_eax, cpuid_ecx, 'Implementation hardware features')
            self.msg('   EAX - Intel-specific features  :  %08x'   % eax)
            self.msg('   EDX - AMD-specific features    :  %08x'   % edx)
        else:
            (eax, ebx, ecx, edx) = self.cpuid_info (cpuid_eax, cpuid_ecx, '')
        return

    ##
    ##  print_synthetic_msrs
    ##
    def print_synthetic_msrs(self):
        self.msg('')
        self.msg('*** Hypervisor Synthetic MSRs ***')

        for addr in sorted(msrs.keys()):
            name = get_msr_name(addr)
            try:
                result = "0x%08x_%08x" % self.rdmsr(addr)
            except Exception as e:
                result = str(e)
            self.msg('RDMSR [%040s = 0x%08x] :  %s' % (name, addr, result))
        return
 
    ##
    ##  scan_hypercalls
    ##
    def scan_hypercalls(self, code_list):
        for call_code in code_list:
            data = self.get_initial_data(GOOD_PARAMS_STATUSES, call_code, 112)
            self.dbg('PROBING HYPERCALL: 0x%04x' % call_code)
            for buffer in data:
                try:
                    self.dbg('- FAST HYPERCALL')
                    hciv    = hv_hciv(0, 0, call_code, 1)
                    result  = self.hv.hypercall64_extended_fast(hciv, buffer) & 0xFFFF
                    hv_rep  = 0
                    hv_fast = 1
                    if result == HV_STATUS_INVALID_HYPERCALL_INPUT:
                        self.dbg('- JUST HYPERCALL')
                        hciv = hv_hciv(0, 0, call_code, 0)
                        result = self.hv.hypercall64_memory_based(hciv, buffer) & 0xFFFF
                        hv_fast = 0
                        if result == HV_STATUS_INVALID_HYPERCALL_INPUT:
                            self.dbg('- FAST REP HYPERCALL')
                            hciv   = hv_hciv(0, 1, call_code, 1)
                            result = self.hv.hypercall64_extended_fast(hciv, buffer) & 0xFFFF
                            hv_rep = 1
                            if result == HV_STATUS_INVALID_HYPERCALL_INPUT:
                                self.dbg('- REP HYPERCALL')
                                hciv = hv_hciv(0, 1, call_code, 0)
                                result  = self.hv.hypercall64_memory_based(hciv, buffer) & 0xFFFF
                                hv_fast = 0
                            else:
                                hv_fast = 1
                    if result <> HV_STATUS_INVALID_HYPERCALL_CODE:
                        self.hv_hypercalls[call_code] = [hv_rep, hv_fast, result]
                except Exception as e:
                    self.msg('Exception on hypercall (0x%08x): %s' % (call_code, str(e)))
        return

    ##
    ##  scan_partitionid
    ##
    def scan_partitionid(self, id_list):
        invalid_partition = 0
        for i in id_list:
            hciv = hv_hciv(0, 0, 0x0041)
            buffer = pack ('<Q', i)
            result = self.hv.hypercall64_memory_based(hciv, buffer) & 0xFFFF
            if result == HV_STATUS_ACCESS_DENIED:
                self.hv_partitionid[i] = 1
            if result == HV_STATUS_INVALID_PARTITION_ID:
                invalid_partition = 1
        if invalid_partition == 0:
            self.hv_partitionid = {}
        return

    ##
    ##  scan_connectionid
    ##
    def scan_connectionid(self, id_list):
        for i in id_list:
            hciv = hv_hciv(0, 0, HV_POST_MESSAGE)
            buffer = pack ('<LLLLQ', i, 0x0, 0x1, 8, 0x0)
            result = self.hv.hypercall64_memory_based(hciv, buffer) & 0xFFFF
            if result <> HV_STATUS_INVALID_CONNECTION_ID:
                if result == HV_STATUS_SUCCESS:
                    self.hv_connectionid[i] = 0x1
                else:
                    hciv = hv_hciv(0, 0, HV_SIGNAL_EVENT)
                    buffer = pack ('<LHH', i, 0x0, 0x0)
                    result = self.hv.hypercall64_memory_based(hciv, buffer) & 0xFFFF
                    self.hv_connectionid[i] = 0x2 if result == HV_STATUS_SUCCESS else 0x3
        return

    ##
    ##  scan_for_success_status
    ##
    def scan_for_success_status(self, i, total_tests):
        statistics = {}
        pattern    = ''
        hc = self.hv_hypercalls[i] if i in self.hv_hypercalls else [0, 0, HV_STATUS_INVALID_HYPERCALL_CODE]
        if hc[2] <> HV_STATUS_SUCCESS:
            for x in xrange(total_tests):
                buffer  = ''
                buffer += '\x00' * randint(0 ,8) + chr(getrandbits(8))
                buffer += '\x00' * randint(0, 8) + chr(getrandbits(8))
                buffer += '\x00' * randint(0, 8) + chr(getrandbits(8))
                buffer += '\x00' * randint(0, 8) + chr(getrandbits(8))
                buffer += '\x00' * 32
                hciv   = hv_hciv(0, hc[0], i, 0)
                result = self.hv.hypercall64_memory_based(hciv, buffer)
                rep_completed = (result >> 32) & 0x0FFF
                result        = result & 0xFFFF
                statistics[result] = 1 if result not in statistics else statistics[result]  + 1
                if result == HV_STATUS_SUCCESS:
                    pattern = buffer
                    break
                if result == HV_STATUS_ACCESS_DENIED:
                    pattern = buffer
            self.msg('*************** Status codes statistics: *****************')
            for n in sorted(statistics.keys()):
                status = get_hypercall_status(n, 'Not defined')
                self.msg('%50s: %d' % (status, statistics[n]) )
            self.hex('Input Parameters', pattern[:0x20])
        else:
            self.msg('')
            self.msg('Hypercall status: SUCCESS')
        return

    ##
    ##  scan_input_parameters
    ##
    def scan_input_parameters(self, i, maxlen):
        matrix = [[0 for x in xrange(0x101)] for y in xrange(maxlen)]
        hc = self.hv_hypercalls[i] if i in self.hv_hypercalls else [0, 0, HV_STATUS_INVALID_HYPERCALL_CODE]
        iv = self.get_initial_data(GOOD_PARAMS_STATUSES, i, 32)[0]
        self.msg('Start scanning ...')
        for l in xrange(maxlen):
            for v in xrange(0x100):
                s = list(iv)
                s[l]   = chr(v)
                buffer = ''.join(s)
                hciv   = hv_hciv(0, hc[0], i, 0)
                result = self.hv.hypercall64_memory_based(hciv, buffer) & 0xFFFF
                matrix[l][v] = result
        self.param_matrix_status[i] = matrix
        self.msg('Done!')
        return

    ##
    ##  print_input_parameters
    ##
    def print_input_parameters(self, i, maxlen, status_list):
        matrix = self.param_matrix_status[i]
        for l in xrange(maxlen):
            x   = 0
            ranges = []
            for v in xrange(0x100):
                if (matrix[l][v] not in status_list) and (matrix[l][v + 1] in status_list):
                    x = v + 1
                if (matrix[l][v] in status_list) and (matrix[l][v + 1] not in status_list):
                    if (x == v):
                        ranges.append('%02X' % x)
                    else:
                        ranges.append('%02X-%02X' % (x, v))
            if (ranges <> ['00-FF']) and (ranges <> []):
                self.msg('  Byte %02d = [ %s ]' % (l, ', '.join(ranges)))
        return

    ##
    ##  input_parameters_fuzzing
    ##
    def input_parameters_fuzzing(self, i, maxlen, status_list, total_tests):
        matrix = self.param_matrix_status[i]
        buffer = self.get_initial_data(GOOD_PARAMS_STATUSES, i, 32)[0]
        self.msg('Start input parameters fuzzing ...')
        for x in xrange(total_tests):
            if x % 10000000 == 10000000-1:
                self.msg('%4.0f%% DONE' % (100.0*x/total_tests))
            l = randint(0, maxlen-1)
            v = randint(0, 0x100-1)
            if matrix[l][v] == 1:
                s = list(buffer)
                s[l]   = chr(v)
                buffer = ''.join(s)
                s[randint(0, maxlen-1)] = chr(randint(0, 0xFF))
                s[randint(0, maxlen-1)] = chr(randint(0, 0xFF))
                if self.hv_hypercalls[i][0] in status_list:
                    hciv = hv_hciv(0, 1, i, 0)
                else:
                    hciv = hv_hciv(0, 0, i, 0)
                result = self.hv.hypercall64_memory_based(hciv, ''.join(s)) & 0xFFFF
        self.msg('DONE!')
        return

    ##
    ##  print_hypercall_status
    ##
    def print_hypercall_status(self):
        self.msg('')
        self.msg('*** Hypervisor Hypercall Status Codes ***')
        status_list = [HV_STATUS_INVALID_HYPERCALL_CODE]
        for i in sorted(self.hv_hypercalls.keys()):
            hc     = self.hv_hypercalls[i]
            status = get_hypercall_status(hc[2])
            hcname = get_hypercall_name(i)
            if status not in status_list:
                self.msg("HYPERV_HYPERCALL REP:%d FAST:%d %04x  %02x  %-40s '%s'" % (hc[0], hc[1], i, hc[2], status, hcname) )
        return

    ##
    ##  print_partitionid
    ##
    def print_partitionid(self):
        self.msg('')
        self.msg('*** Hypervisor Partition IDs ***')
        if len(self.hv_partitionid) == 0:
            self.msg('  was not able to dertemine Partition IDs')
        else:
            for i in sorted(self.hv_partitionid.keys()):
                self.msg('%08x' % i)
        return

    ##
    ##  print_partition_properties
    ##
    def print_partition_properties(self):
        self.msg('')
        self.msg('*** Partition properties ***')
        for partid in sorted(self.hv_partitionid.keys()):
            for n in xrange(0x10):
                for m in xrange(0x10):
                    hciv = hv_hciv(0, 0, HV_GET_PARTITION_PROPERTY)
                    prop = (n << 16) + m
                    buffer = pack('<QLL', partid, prop, 0)
                    result = self.hv.hypercall64_memory_based(hciv, buffer, 8)
                    if result == HV_STATUS_SUCCESS:
                        self.msg('  Partition: %08x  Property: %08x  Value: %016x' % (partid, prop, unpack('<Q', self.hv.output)[0]))
        return

    ##
    ##  set_partition_property
    ##
    def set_partition_property(self, part, prop, value):
        hciv   = hv_hciv(0, 0, HV_SET_PARTITION_PROPERTY)
        buffer = pack('<QLLQ', part, prop, 0, value)
        result = self.hv.hypercall64_memory_based(hciv, buffer)
        status = get_hypercall_status(result, '0x%08x' % result)
        self.msg('>>> Setting partition property:  Partition: %08x  Property: %08x  Value: %016x  Status: %s' % (part, prop, value, status))
        return

    ##
    ##  print_connectionid
    ##
    def print_connectionid(self, status_list):
        self.msg('')
        self.msg('*** Hypervisor Connection IDs ***')
        for i in sorted(self.hv_connectionid.keys()):
            connid = self.hv_connectionid[i]
            self.msg('%08x  %02x  %s' % (i, connid, hv_porttype[connid]))
        return

    ##
    ##  custom_fuzzing
    ##
    def custom_fuzzing(self, call_code, total_tests):
        statistics = {}
        buffer = ''.join( [chr(randint(0,255)) for i in xrange(0, 112)] )
        hcname = get_hypercall_name(call_code)

        if hcname == 'HvConnectPort':
            return
            self.msg('Hypercall: %s ' % hcname)
            hciv = hv_hciv(0, 0, call_code)
            for i in xrange(0x0, 0xFFFFF):
                buffer = pack ('<5Q', i & 0xF, (i >> 4) & 0xF, (i >> 8) & 0xF, (i >> 12) & 0xF, (i >> 16) & 0xF ) 
                result = self.hv.hypercall64_memory_based(hciv, buffer)
                statistics[result] = 1 if result not in statistics else statistics[result]  + 1

        elif hcname == 'HvPostMessage':
            self.msg('Hypercall: %s ' % hcname)
            hciv = hv_hciv(0, 0, call_code)
            for connid in sorted(self.hv_connectionid.keys()):
                if self.hv_connectionid[connid] == HV_PORT_TYPE_MESSAGE:
                    self.msg('Connection ID: : %08x' % connid)
                    for i in xrange(0x100, 0x1000):
                        messagetype = 0x7FFFFFFF & getrandbits(32)
                        payloadsize = randint(0, 240)
                        message0    = getrandbits(8)
                        buffer = pack ('<4LQ', connid, 0, messagetype, payloadsize, message0 )
                        result = hv.hypercall64_memory_based(hciv, buffer)
                        statistics[result] = 1 if result not in statistics else statistics[result]  + 1
                        self.dbg('HvPostMessage: %s %s' % (get_hypercall_status(result), binascii.hexlify(buffer)))

        elif hcname == 'HvSignalEvent':
            self.msg('Hypercall: %s ' % hcname)
            hciv = hv_hciv(0, 0, call_code)
            for connid in sorted(self.hv_connectionid.keys()):
                if self.hv_connectionid[connid] == HV_PORT_TYPE_EVENT:
                    self.msg('Connection ID: %08x' % connid)
                    for i in xrange(min(total_tests, 0xFFFF)):
                        buffer = pack ('<LHH', connid, 0, i)
                        result = self.hv.hypercall64_memory_based(hciv, buffer)
                        statistics[result] = 1 if result not in statistics else statistics[result]  + 1

        if len(statistics) > 0:
            self.msg('*************** Status codes statistics: *****************')
            for i in sorted(statistics.keys()):
                self.msg('%50s: %d' % (get_hypercall_status(i), statistics[i]) )

        return
