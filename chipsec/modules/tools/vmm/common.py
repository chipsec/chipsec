# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2020, Intel Corporation
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
Common functionality for VMM related modules/tools
"""

import sys
import socket
import struct
import random
import os.path
import json
import pprint
from random import getrandbits, randint
from time import strftime, localtime
from chipsec.module_common import BaseModule
from chipsec.library.defines import DD
from typing import Dict, List, Tuple


class BaseModuleDebug(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)
        self.debug = False
        self.prompt = ''

    def __del__(self) -> None:
        pass

    ##
    # msg
    ##
    def msg(self, message: str) -> None:
        sys.stdout.write(f'[{self.prompt}]  {message}\n')
        return

    ##
    # err
    ##
    def err(self, message: str) -> None:
        sys.stdout.write(f'[{self.prompt}]  **** ERROR: {message}\n')
        return

    ##
    # dbg
    ##
    def dbg(self, message: str):
        if self.debug:
            sys.stdout.write(f'[{self.prompt}]  {message}\n')
        return

    ##
    # hex
    ##
    def hex(self, title: str, data:str, w=16) -> None:
        if title and data:
            title = f'{"-" * 6}{title}{"-" * w * 3}'
            sys.stdout.write(f'[{self.prompt}]  {title[:w * 3 + 15]}')
        a = 0
        for c in data:
            if a % w == 0:
                sys.stdout.write(f'\n[{self.prompt}]  {a:08X}: ')
            elif a % w % 8 == 0:
                sys.stdout.write('| ')
            sys.stdout.write(f'{ord(c):02X} ')
            a = a + 1
        sys.stdout.write('\n')
        return

    ##
    # fatal
    ##
    def fatal(self, message: str) -> None:
        sys.stdout.write(f'[{self.prompt}]  **** FATAL: {message}\n')
        exit(1)
        return

    ##
    # info_bitwise
    ##
    def info_bitwise(self, reg: int, desc: Dict[int, str]) -> None:
        i = 0
        while reg != 0:
            if i in desc:
                self.msg(f'       Bit {i:2d}:  {(reg & 0x1):d}  {desc[i]}')
            i += 1
            reg = reg >> 1
        return


class BaseModuleSupport(BaseModuleDebug):
    def __init__(self):
        BaseModuleDebug.__init__(self)
        self.initial_data = []
        self.path = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(self.path, 'hv', 'initial_data.json'), 'r') as json_file:
            self.initial_data = json.load(json_file)
        self.statistics = {}
        self.hv_connectionid = {}

    def __del__(self) -> None:
        # self.dump_initial_data('initial_data_auto_generated.json')
        BaseModuleDebug.__del__(self)

    def stats_reset(self) -> None:
        self.statistics = {}
        return

    def stats_event(self, name: str) -> None:
        self.statistics[name] = self.statistics.get(name, 0) + 1
        return

    def stats_print(self, title: str) -> None:
        self.msg('')
        self.msg(f' {title} '.center(72 - len(self.prompt), '*'))
        for name in sorted(self.statistics, key=self.statistics.get, reverse=True):
            self.msg(f'{name:50} : {self.statistics[name]:d}')
        self.msg('')
        return

    def get_initial_data(self, statuses: List[str], vector: int, size: int, padding='\x00') -> List[str]:
        connectionid_message = [(' '.join([f'{x:02x}' for x in DD(k)])) for k, v in self.hv_connectionid.items() if v == 1]
        connectionid_event = [(' '.join([f'{x:02x}' for x in DD(k)])) for k, v in self.hv_connectionid.items() if v == 2]
        result = []
        for status in statuses:
            for item in self.initial_data:
                if (int(item['vector'], 16) == vector) and (item['status'] == status):
                    data = item['data']
                    data = data.replace('CONNECTION_ID_MESSAGE_TYPE', random.choice(connectionid_message))
                    data = data.replace('CONNECTION_ID_EVENT_TYPE', random.choice(connectionid_event))
                    buffer = str(bytearray.fromhex(data)) + padding * size
                    result.append(buffer[:size])
        if not result:
            result = [padding * size]
        return result

    def add_initial_data(self, vector: int, buffer: str, status: str) -> None:
        found = False
        buffer = buffer.rstrip('\x00')
        buffer = ' '.join(f'{x:02x}' for x in buffer)
        for item in self.initial_data:
            if int(item['vector'], 16) == vector:
                if item['data'] == buffer:
                    found = True
                    break
        if not found:
            self.initial_data.append({'vector': f'{vector:02X}', 'status': status, 'data': buffer})
        return

    def dump_initial_data(self, filename: str) -> None:
        if self.initial_data:
            with open(self.path + filename, 'w') as json_file:
                json.dump(self.initial_data, json_file, indent=4)
        return


class BaseModuleHwAccess(BaseModuleSupport):

    ##
    # cpuid_info
    ##
    def cpuid_info(self, eax: int, ecx: int, desc: str) -> Tuple[int, int, int, int]:
        val = self.cs.cpu.cpuid(eax, ecx)
        self.msg('')
        self.msg(f'CPUID.{eax:X}h.{ecx:X}h > {desc}')
        self.msg(f'EAX: 0x{val[0]:08X} EBX: 0x{val[1]:08X} ECX: 0x{val[2]:08X} EDX: 0x{val[3]:08X}')
        return val

    ##
    # rdmsr
    ##
    def rdmsr(self, msr: int) -> Tuple[int, int]:
        eax, edx = (0, 0)
        temp = sys.stdout
        sys.stdout = open(os.devnull, 'wb')
        try:
            for tid in range(self.cs.msr.get_cpu_thread_count()):
                (eax, edx) = self.cs.msr.read_msr(tid, msr)
        except:
            sys.stdout = temp
            raise
        sys.stdout = temp
        return (edx, eax)

    ##
    # wrmsr
    ##
    def wrmsr(self, msr: int, value: int) -> None:
        temp = sys.stdout
        sys.stdout = open(os.devnull, 'wb')
        try:
            for tid in range(self.cs.msr.get_cpu_thread_count()):
                self.cs.msr.write_msr(tid, msr, value & 0xFFFFFFFF, value >> 32)
        except:
            sys.stdout = temp
            raise
        sys.stdout = temp
        return

### COMMON ROUTINES ############################################################


def weighted_choice(choices: List[Tuple[int, float]]) -> int:
    total = sum(w for c, w in choices)
    r = random.uniform(0, total)
    x = 0
    for c, w in choices:
        if x + w >= r:
            return c
        x += w
    assert False, 'Invalid parameters'


def rand_dd(n: int, rndbytes: int = 1, rndbits: int = 1) -> List[int]:
    weights = [(0x00000000, 0.85), (0xFFFFFFFF, 0.10), (0xFFFF0000, 0.05), (0xFFFFFF00, 0.05)]
    buffer = b''
    for i in range(n):
        buffer += DD(weighted_choice(weights))
    buffer = list(buffer)
    for i in range(rndbytes):
        pos = randint(0, len(buffer) - 1)
        buffer[pos] = randint(0, 255)
    for i in range(rndbits):
        pos = randint(0, len(buffer) - 1)
        buffer[pos] = (buffer[pos]) ^ (0x1 << randint(0, 7))
        buffer = ''.join(buffer)
    return buffer


def overwrite(buffer: bytes, string: bytes, position: int) -> bytes:
    return buffer[:position] + string + buffer[position + len(string):]


def get_int_arg(arg: str) -> int:
    try:
        ret = int(eval(arg))
    except:
        print('\n  ERROR: Invalid parameter\n')
        exit(1)
    return ret


def hv_hciv(rep_start: int, rep_count: int, call_code: int, fast: int = 0) -> int:
    return (((rep_start & 0x0FFF) << 48) + ((rep_count & 0x0FFF) << 32) + ((fast & 0x1) << 16) + (call_code & 0xFFFF))


def uuid(id: bytes) -> str:
    return '{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}'.format(*struct.unpack('<IHH8B', id))

### OPTIONAL ROUTINES ##########################################################


class session_logger:
    def __init__(self, log: bool, details: str):
        self.defstdout = sys.stdout
        self.log = log
        self.log2term = True
        self.log2file = True
        if self.log:
            logpath = f'logs/{strftime("%Yww%W.%w", localtime())}/'
            logfile = f'{details}-{strftime("%H%M", localtime())}.log'
            try:
                os.makedirs(logpath)
            except OSError:
                pass
            self.terminal = sys.stdout
            self.logfile = open(logpath + logfile, 'a')

    def write(self, message: str) -> None:
        if self.log and self.log2term:
            self.terminal.write(message)
        if self.log and self.log2file:
            self.logfile.write(message)

    def flush(self) -> None:
        if self.log and self.log2term:
            self.terminal.flush()
        if self.log and self.log2file:
            self.logfile.flush()

    def closefile(self) -> None:
        if self.log:
            self.logfile.close()
            sys.stdout = self.defstdout
