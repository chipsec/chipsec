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
Xen specific hypercall functionality
"""

import collections
from chipsec.modules.tools.vmm.xen.define import *
from chipsec.hal.vmm import *
from chipsec.module_common import *
from chipsec.modules.tools.vmm.common import *

SM_RANGE = {'masks': [0x00000000000000FF]}
MD_RANGE = {'masks': [0x000000000000FFFF]}
XL_RANGE = {'masks': [0xFFFFFFFFFFFFFFFF]}


class XenHypercall(BaseModuleHwAccess):
    def __init__(self):
        BaseModuleHwAccess.__init__(self)
        self.vmm = VMM(self.cs)
        self.vmm.init()
        self.hypervisor_present = False
        self.hypercalls = {}
        self.buff_va = 0
        self.buff_pa = 0
        (self.buff_va, self.buff_pa) = self.cs.mem.alloc_physical_mem(0x1000, 0xFFFFFFFFFFFFFFFF)
        if self.buff_pa == 0:
            raise Exception("[*] Could not allocate memory!")
        # define initial args for hypercall fuzzing
        self.hypercall_args = {
            MEMORY_OP: {'args': [xenmem_commands.keys(), self.buff_va]},
            SET_TIMER_OP: {'args': [XL_RANGE, XL_RANGE]},
            XEN_VERSION: {'args': [xen_version_commands.keys(), self.buff_va]},
            CONSOLE_IO: {'args': [console_io_commands.keys(), MD_RANGE, self.buff_va]},
            GRANT_TABLE_OP: {'args': [SM_RANGE, self.buff_va, XL_RANGE]},
            SCHED_OP: {'args': [schedop_commands.keys(), self.buff_va]},
            EVENT_CHANNEL_OP: {'args': [evtchop_commands.keys(), self.buff_va]},
            NMI_OP: {'args': [XL_RANGE, XL_RANGE]},
            HVM_OP: {'args': [hvmop_commands.keys(), self.buff_va]},
            TMEM_OP: {'args': [self.buff_va]},
            XENPMU_OP: {'args': [xenpmuop_commands.keys(), self.buff_va]},
            SYSCTL: {'args': [self.buff_va]},
            DOMCTL: {'args': [self.buff_va]},
            ARCH_1: {'args': [self.buff_va]},
        }

    def get_value(self, arg):
        if type(arg) in [dict]:
            value = random.choice(arg.get('masks')) & random.getrandbits(64)
        elif type(arg) in [list, tuple, range]:
            value = random.choice(arg)
        else:
            value = arg
        return value

    ##
    # hypercall
    ##
    def hypercall(self, args, size=0, data=''):
        data = data.ljust(4096, '\x00')[:4096]
        self.cs.mem.write_physical_mem(self.buff_pa, len(data), data)
        self.dbg(f'ARGS: {" ".join([f"{x:016X}" for x in args])}  DATA: {data[:32].hex()}')
        try:
            rax = self.vmm.hypercall64_five_args(*args)
            val = self.cs.mem.read_physical_mem(self.buff_pa, size) if size > 0 else ''
        except Exception as e:
            self.dbg(f'Exception on hypercall (0x{args[0]:08X}): {str(e)}')
            return {'exception': True, 'status': 0xFFFFFFFFFFFFFFFF, 'buffer': str(e)}
        return {'exception': False, 'status': rax, 'buffer': val}

    ##
    # xen_version
    ##
    def xen_version(self, cmd, size=0, data=''):
        return self.hypercall((XEN_VERSION, cmd, self.buff_va), size, data)

    ##
    # get_hypervisor_info
    ##
    def get_hypervisor_info(self):
        info = {}

        if not self.xen_version(XENVER_VERSION)['exception']:
            version = self.xen_version(XENVER_VERSION)
            extra_version = self.xen_version(XENVER_EXTRAVERSION, 16)
            compile_info = self.xen_version(XENVER_COMPILE_INFO, 140)
            capabilities = self.xen_version(XENVER_CAPABILITIES, 1024)
            changeset = self.xen_version(XENVER_CHANGESET, 64)
            platform_parameters = self.xen_version(XENVER_PLATFORM_PARAMETERS, 8)
            pagesize = self.xen_version(XENVER_PAGESIZE)
            guest_handle = self.xen_version(XENVER_GUEST_HANDLE)
            command_line = self.xen_version(XENVER_COMMANDLINE, 1024)

            info['extra_version'] = extra_version['buffer'].strip('\x00')
            info['xen_major'] = (version['status'] >> 16) & 0xFFFF
            info['xen_minor'] = version['status'] & 0xFFFF
            info['xen_version'] = f'{info["xen_major"]:d}.{info["xen_minor"]:d}{extra_version["buffer"]}'
            info['compiler'] = compile_info['buffer'][:64].strip('\x00')
            info['compile_by'] = compile_info['buffer'][64:80].strip('\x00')
            info['compile_domain'] = compile_info['buffer'][80:112].strip('\x00')
            info['compile_date'] = compile_info['buffer'][112:140].strip('\x00')
            info['capabilities'] = capabilities['buffer'].strip('\x00')
            info['changeset'] = changeset['buffer'].strip('\x00')
            info['platform_parameters'] = struct.unpack('<Q', platform_parameters['buffer'])[0]
            info['pagesize'] = pagesize['status']
            info['guest_handle'] = guest_handle['status']
            info['command_line'] = command_line['buffer'].strip('\x00')

            info['features'] = {}
            for i in range(0x100):
                feature = self.xen_version(XENVER_GET_FEATURES, 8, struct.pack('<LL', i, 0))
                if feature['exception'] == False:
                    values = struct.unpack('<LL', feature['buffer'])
                    info['features'][values[0]] = values[1]

        return info

    ##
    # print_hypervisor_info
    ##
    def print_hypervisor_info(self, info):
        features = ', '.join([f'F{k:d}={v:016X}' for k, v in info['features'].items() if v != 0])
        self.msg(f'XEN Hypervisor is present!')
        self.msg(f'          Version : {info["xen_version"]}')
        self.msg(f'         Compiler : {info["compiler"]}')
        self.msg(f'       Compile by : {info["compile_by"]}')
        self.msg(f'   Compile Domain : {info["compile_domain"]}')
        self.msg(f'     Compile Date : {info["compile_date"]}')
        self.msg(f'     Capabilities : {info["capabilities"]}')
        self.msg(f'       Change Set : {info["changeset"]}')
        self.msg(f'  Platform Params : {info["platform_parameters"]:016X}')
        self.msg(f'         Features : {features}')
        self.msg(f'        Page size : {info["pagesize"]:016X}')
        self.msg(f'     Guest Handle : {info["guest_handle"]:016X}')
        self.msg(f'     Command Line : {info["command_line"]}')

    def scan_hypercalls(self, vector_list):
        for vector in vector_list:
            args = self.hypercall_args.get(vector, {}).get('args', [])
            result = self.hypercall([vector] + [0 for a in args])
            if (result['exception'] == False) and (result['status'] != get_invalid_hypercall_code()):
                self.hypercalls[vector] = result
                self.add_initial_data(vector, result['buffer'], get_hypercall_status(result['status'], True))
        return

    def print_hypercall_status(self):
        self.msg('')
        self.msg('*** Hypervisor Hypercall Status Codes ***')
        for vector in sorted(self.hypercalls.keys()):
            data = self.hypercalls[vector]
            name = get_hypercall_name(vector)
            status = get_hypercall_status_extended(data['status'])
            self.msg(f'HYPERCALL {vector:04X}  {data["status"]:016X}  {status:45} \'{name}\'')
        return

    def fuzz_hypercall(self, code, iterations):
        rule = self.hypercall_args.get(code, {})
        if not rule:
            self.msg("WARNING: Fuzzing rule is not defined for this hypercall!")
        args = rule.get('args', [])
        self.msg(f'Fuzzing {get_hypercall_name(code, "Unknown")} (0x{code:02X}) hypercall')
        self.stats_reset()
        for it in range(iterations):
            data = list('\x00' * 32)
            data[randint(0, len(data) - 1)] = chr(getrandbits(8))
            data[randint(0, len(data) - 1)] = chr(getrandbits(8))
            data = ''.join(data)
            values = [code] + [self.get_value(a) for a in args]
            result = self.hypercall(values, 8, data)
            if result['exception']:
                self.stats_event('exception')
            else:
                self.stats_event(get_hypercall_status_extended(result['status']))
        self.stats_print('Hypercall status codes')
        return

    def fuzz_hypercalls_randomly(self, codes, iterations):
        for it in range(iterations):
            code = random.choice(codes)
            rule = self.hypercall_args.get(code, {})
            if not rule:
                self.msg("WARNING: Fuzzing rule is not defined for this hypercall!")
            args = rule.get('args', [])
            data = list('\x00' * 32)
            data[randint(0, len(data) - 1)] = chr(getrandbits(8))
            data[randint(0, len(data) - 1)] = chr(getrandbits(8))
            data = ''.join(data)
            values = [code] + [self.get_value(a) for a in args]
            result = self.hypercall(values, 8, data)
        return
