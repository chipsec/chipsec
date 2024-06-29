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
A tool to test SMI handlers for pointer validation vulnerabilities

Reference:
    - Presented in CanSecWest 2015:
        - c7zero.info: `A New Class of Vulnerability in SMI Handlers of BIOS/UEFI Firmware <http://www.c7zero.info/stuff/ANewClassOfVulnInSMIHandlers_csw2015.pdf>`_


Usage:
``chipsec_main -m tools.smm.smm_ptr -l log.txt \``
``[-a <mode>,<config_file>|<smic_start:smic_end>,<size>,<address>]``

- ``mode``: SMI fuzzing mode

    * ``config`` = use SMI configuration file <config_file>
    * ``fuzz`` = fuzz all SMI handlers with code in the range <smic_start:smic_end>
    * ``fuzzmore`` = fuzz mode + pass 2nd-order pointers within buffer to SMI handlers
    * ``scan`` = fuzz mode + time measurement to identify SMIs that trigger long-running code paths
- ``size``: size of the memory buffer (in Hex)
- ``address``: physical address of memory buffer to pass in GP regs to SMI handlers (in Hex)

    * ``smram`` = option passes address of SMRAM base (system may hang in this mode!)

In ``config`` mode, SMI configuration file should have the following format

::

    SMI_code=<SMI code> or *
    SMI_data=<SMI data> or *
    RAX=<value of RAX> or * or PTR or VAL
    RBX=<value of RBX> or * or PTR or VAL
    RCX=<value of RCX> or * or PTR or VAL
    RDX=<value of RDX> or * or PTR or VAL
    RSI=<value of RSI> or * or PTR or VAL
    RDI=<value of RDI> or * or PTR or VAL
    [PTR_OFFSET=<offset to pointer in the buffer>]
    [SIG=<signature>]
    [SIG_OFFSET=<offset to signature in the buffer>]
    [Name=<SMI name>]
    [Desc=<SMI description>]

Where:

    - ``[]``: optional line
    - ``*``: Don't Care (the module will replace * with 0x0)
    - ``PTR``: Physical address SMI handler will write to (the module will replace PTR with physical address provided as a command-line argument)
    - ``VAL``: Value SMI handler will write to PTR address (the module will replace VAL with hardcoded _FILL_VALUE_xx)

Examples:

    >>> chipsec_main.py -m tools.smm.smm_ptr
    >>> chipsec_main.py -m tools.smm.smm_ptr -a fuzzmore,0x0:0xFF -l smm.log
    >>> chipsec_main.py -m tools.smm.smm_ptr -a scan,0x0:0xff

.. warning ::

    - This is a potentially destructive test

"""

import struct
import os
import sys

from chipsec.module_common import BaseModule
from chipsec.library.returncode import ModuleResult
from chipsec.library.file import write_file
from chipsec.library.logger import print_buffer_bytes
from chipsec.hal.interrupts import Interrupts
from chipsec.library.exceptions import BadSMIDetected
from chipsec.helper.oshelper import OsHelper


#################################################################
# Fuzzing configuration
#################################################################

#
# Logging option
#

# False - better performance, True - better results tracking
DUMP_MEMORY_ON_DETECT = False
# False - better performance, True - better results tracking
FLUSH_OUTPUT_ALWAYS = False
# makes sure SMI code is logged in case of a crash
FLUSH_OUTPUT_BEFORE_SMI = True
FLUSH_OUTPUT_AFTER_SMI = True
# dump all registers in log before every SMI (True - large size of log file)
DUMP_GPRS_EVERY_SMI = True

#
# SMI fuzzing options
#

# stop fuzzing after the first potential issue detected
FUZZ_BAIL_ON_1ST_DETECT = True

# Consider SMI handler subfunctions are passed in RCX GP register
# Fuzz RCX as SMI subfunctions: from 0 to MAX_SMI_FUNCTIONS
# False - better performance, True - smarter fuzzing
FUZZ_SMI_FUNCTIONS_IN_ECX = True
MAX_SMI_FUNCTIONS = 0x10

# Max value of the value written to SMI data port (0xB3)
MAX_SMI_DATA = 0x100

# Pass the pointer to SMI handlers in all general-purpose registers
# rather than in one register
# True - faster, False - gives you specific GPR that the vulnerable SMI handler is consuming
#
PTR_IN_ALL_GPRS = False

# SMI handler may take a pointer/PA from (some offset of off) address passed in GPRs and write to it
# Treat contents at physical address passed in GPRs as pointers and check contents at that pointer
# If they changed, SMI handler might have modified them
#MODE_SECOND_ORDER_BUFFER  = True

# Max offset of the pointer (physical address)
# of the 2nd order buffer written in the memory buffer passed to SMI
MAX_PTR_OFFSET_IN_BUFFER = 0x20

# very obscure option, don't even try to understand
GPR_2ADDR = False

# Defines the time percentage increase at which the SMI call is considered to
# be long-running
OUTLIER_THRESHOLD = 33.3

# SMI count MSR
MSR_SMI_COUNT = 0x00000034

#
# Defaults
#
_FILL_VALUE_QWORD = 0x5A5A5A5A5A5A5A5A
_FILL_VALUE_BYTE = 0x5A
_SMI_CODE_DATA = 0x0
_MEM_FILL_VALUE = b'\x11'
_MEM_FILL_SIZE = 0x500
_MAX_ALLOC_PA = 0xFFFFFFFF
_DEFAULT_GPRS = {'rax': _FILL_VALUE_QWORD, 'rbx': _FILL_VALUE_QWORD, 'rcx': _FILL_VALUE_QWORD, 'rdx': _FILL_VALUE_QWORD, 'rsi': _FILL_VALUE_QWORD, 'rdi': _FILL_VALUE_QWORD}

_pth = 'smm_ptr'


class gprs_info:
    def __init__(self, value):
        self.gprs = value

    def __repr__(self):
        return f"rax={self.gprs['rax']:02X} rbx={self.gprs['rbx']:02X} rcx={self.gprs['rcx']:02X}, " \
               f"rdx={self.gprs['rdx']:02X} rsi={self.gprs['rsi']:02X} rdi={self.gprs['rdi']:02X}"


class smi_info:
    def __init__(self, value):
        self.duration = value
        self.gprs = _DEFAULT_GPRS
        self.code = None
        self.data = None

    def update(self, value, code, data, gprs):
        self.duration = value
        self.gprs = gprs
        self.code = code
        self.data = data

    def get_info(self):
        if self.code is None:
            return None
        else:
            return f"duration {self.duration} code {self.code:02X} data {self.data:02X} ({gprs_info(self.gprs)})"


class scan_track:
    def __init__(self):
        self.clear()
        self.hist_smi_duration = 0
        self.hist_smi_num = 0
        self.outliers_hist = 0
        self.helper = OsHelper().get_default_helper()
        self.helper.init()
        self.smi_count = self.get_smi_count()

    def __del__(self):
        self.helper.close()

    def get_smi_count(self):
        count = -1
        #
        # The SMI count is the same on all CPUs
        #
        cpu = 0
        try:
            count = self.helper.read_msr(cpu, MSR_SMI_COUNT)
            count = count[1] << 32 | count[0]
        except UnimplementedAPIError:
            pass
        return count

    def valid_smi_count(self):
        valid = False
        count = self.get_smi_count()
        if (count == -1):
            return True
        elif (count == self.smi_count + 1):
            valid = True
        self.smi_count = count
        if not valid:
            print("SMI contention detected", file=sys.stderr)
        return valid

    def find_address_in_regs(self, gprs):
        for key, value in gprs.items():
            if key == 'rcx':
                continue
            if value != _FILL_VALUE_QWORD:
                return key

    def clear(self):
        self.max = smi_info(0)
        self.min = smi_info(2**32-1)
        self.outlier = smi_info(0)
        self.acc_smi_duration = 0
        self.acc_smi_num = 0
        self.avg_smi_duration = 0
        self.avg_smi_num = 0
        self.outliers = 0
        self.code = None
        self.confirmed = False

    def add(self, duration, code, data, gprs, confirmed=False):
        if not self.code:
            self.code = code
        outlier = self.is_outlier(duration)
        if not outlier:
            self.acc_smi_duration += duration
            self.acc_smi_num += 1
            if duration > self.max.duration:
                self.max.update(duration, code, data, gprs.copy())
            elif duration < self.min.duration:
                self.min.update(duration, code, data, gprs.copy())
        else:
            self.outliers += 1
            self.outliers_hist += 1
            self.outlier.update(duration, code, data, gprs.copy())
        self.confirmed = confirmed

    def avg(self):
        if self.avg_smi_num or self.acc_smi_num:
            self.avg_smi_duration = ((self.avg_smi_duration * self.avg_smi_num) + self.acc_smi_duration) / (self.avg_smi_num + self.acc_smi_num)
            self.avg_smi_num += self.acc_smi_num
            self.hist_smi_duration = ((self.hist_smi_duration * self.hist_smi_num) + self.acc_smi_duration) / (self.hist_smi_num + self.acc_smi_num)
            self.hist_smi_num += self.acc_smi_num
            self.acc_smi_duration = 0
            self.acc_smi_num = 0

    def is_outlier(self, value):
        self.avg()
        ret = False
        if self.avg_smi_duration and value > self.avg_smi_duration * (1 + OUTLIER_THRESHOLD / 100):
            ret = True
        if self.hist_smi_duration and value > self.hist_smi_duration * (1 + OUTLIER_THRESHOLD / 100):
            ret = True
        return ret

    def skip(self):
        return self.outliers or self.confirmed

    def found_outlier(self):
        return bool(self.outliers)

    def get_total_outliers(self):
        return self.outliers_hist

    def get_info(self):
        self.avg()
        avg = self.avg_smi_duration or self.hist_smi_duration
        info = f"average {round(avg)} checked {self.avg_smi_num + self.outliers}"
        if self.outliers:
            info += f"\n    Identified outlier: {self.outlier.get_info()}"
        return info

    def log_smi_result(self, logger):
        msg = f'SCANNED: SMI# {self.code:02X} {self.get_info()}'
        if self.found_outlier():
            logger.log_important(msg)
        else:
            logger.log(f'[*] {msg}')


class smi_desc:
    def __init__(self):
        self.smi_code = None
        self.smi_data = None
        self.name = 'smi'
        self.desc = ''
        self.gprs = _DEFAULT_GPRS
        self.ptr_in_buffer = False
        self.ptr = None
        self.ptr_offset = 0
        self.sig = None
        self.sig_offset = 0


def DIFF(s, t, sz):
    return [pos for pos in range(sz) if s[pos] != t[pos]]


def FILL_BUFFER(_fill_byte, _fill_size, _ptr_in_buffer, _ptr, _ptr_offset, _sig, _sig_offset):
    fill_buf = _fill_byte * _fill_size
    if _ptr_in_buffer and (_ptr is not None):
        fill_buf = fill_buf[:_ptr_offset] + struct.pack('=I', _ptr & 0xFFFFFFFF) + fill_buf[_ptr_offset + 4:]
    if _sig is not None:
        fill_buf = fill_buf[:_sig_offset] + _sig + fill_buf[_sig_offset + len(_sig):]
    return fill_buf


class smm_ptr(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)
        self.interrupts = Interrupts(self.cs)
        self.is_check_memory = True
        self.test_ptr_in_buffer = False
        self.fill_byte = _MEM_FILL_VALUE
        self.fill_size = _MEM_FILL_SIZE

    def is_supported(self):
        return True

    def fill_memory(self, _addr, is_ptr_in_buffer, _ptr, _ptr_offset, _sig, _sig_offset):
        #
        # Fill in contents at PA = _addr with known pattern to check later if any SMI handler modifies them
        #
        fill_buf = FILL_BUFFER(self.fill_byte, self.fill_size, is_ptr_in_buffer, _ptr, _ptr_offset, _sig, _sig_offset)

        s = f'[*] Writing 0x{self.fill_size:X} bytes at 0x{_addr:016X}'
        if is_ptr_in_buffer:
            s += f' -> PTR at +0x{_ptr_offset:X}'
        if _sig is not None:
            s += f' -> SIG at +0x{_sig_offset:X}'
        self.logger.log(s)
        self.cs.mem.write_physical_mem(_addr, self.fill_size, fill_buf)

        if self.logger.VERBOSE:
            self.logger.log(f'Filling in contents at PA 0x{_addr:016X}:')
            print_buffer_bytes(fill_buf, 16)

        if is_ptr_in_buffer and _ptr is not None:
            self.logger.log(f'[*] Writing buffer at PA 0x{_ptr:016X} with 0x{self.fill_size:X} bytes \'{self.fill_byte}\'')
            self.cs.mem.write_physical_mem(_ptr, self.fill_size, self.fill_byte * self.fill_size)

        return True

    def send_smi(self, thread_id, smi_code, smi_data, name, desc, rax, rbx, rcx, rdx, rsi, rdi):
        self.logger.log(f'    > SMI {smi_code:02X} (data: {smi_data:02X})')
        if DUMP_GPRS_EVERY_SMI:
            self.logger.log(f'      RAX: 0x{rax:016X}')
            self.logger.log(f'      RBX: 0x{rbx:016X}')
            self.logger.log(f'      RCX: 0x{rcx:016X}')
            self.logger.log(f'      RDX: 0x{rdx:016X}')
            self.logger.log(f'      RSI: 0x{rsi:016X}')
            self.logger.log(f'      RDI: 0x{rdi:016X}')
        self.interrupts.send_SW_SMI(thread_id, smi_code, smi_data, rax, rbx, rcx, rdx, rsi, rdi)
        return True

    def send_smi_timed(self, thread_id, smi_code, smi_data, name, desc, rax, rbx, rcx, rdx, rsi, rdi):
        self.logger.log(f'    > SMI {smi_code:02X} (data: {smi_data:02X})')
        if DUMP_GPRS_EVERY_SMI:
            self.logger.log(f'      RAX: 0x{rax:016X}')
            self.logger.log(f'      RBX: 0x{rbx:016X}')
            self.logger.log(f'      RCX: 0x{rcx:016X}')
            self.logger.log(f'      RDX: 0x{rdx:016X}')
            self.logger.log(f'      RSI: 0x{rsi:016X}')
            self.logger.log(f'      RDI: 0x{rdi:016X}')
        ret = self.interrupts.send_SW_SMI_timed(thread_id, smi_code, smi_data, rax, rbx, rcx, rdx, rsi, rdi)
        duration = ret[7]
        return (True, duration)

    def check_memory(self, _addr, _smi_desc, fn, restore_contents=False):
        _ptr = _smi_desc.ptr
        filler = self.fill_byte * self.fill_size
        #
        # Check if contents have changed at physical address passed in GPRs to SMI handler
        # If changed, SMI handler might have written to that address
        #
        self.logger.log("    < Checking buffers")

        expected_buf = FILL_BUFFER(self.fill_byte, self.fill_size, _smi_desc.ptr_in_buffer, _smi_desc.ptr, _smi_desc.ptr_offset, _smi_desc.sig, _smi_desc.sig_offset)
        buf = self.cs.mem.read_physical_mem(_addr, self.fill_size)
        differences = DIFF(expected_buf, buf, self.fill_size)
        _changed = len(differences) > 0

        if self.logger.VERBOSE:
            self.logger.log(f'Checking contents at PA 0x{_addr:016X}:')
            print_buffer_bytes(buf, 16)
            self.logger.log('Expected contents:')
            print_buffer_bytes(expected_buf, 16)

        if _changed:
            self.logger.log(f'    Contents changed at 0x{_addr:016X} +{differences}')
            if restore_contents:
                self.logger.log(f'    Restoring 0x{self.fill_size:X} bytes at 0x{_addr:016X}')
                self.cs.mem.write_physical_mem(_addr, self.fill_size, expected_buf)
            if DUMP_MEMORY_ON_DETECT:
                _pth_smi = os.path.join(_pth, f'{_smi_desc.smi_code:X}_{_smi_desc.name}')
                if not os.path.exists(_pth_smi):
                    os.makedirs(_pth_smi)
                _f = os.path.join(_pth_smi, fn + '.dmp')
                self.logger.log(f'    Dumping buffer to \'{_f}\'')
                write_file(_f, buf)

        _changed1 = False
        expected_buf = filler
        if _smi_desc.ptr_in_buffer and (_ptr is not None):
            buf1 = self.cs.mem.read_physical_mem(_ptr, self.fill_size)
            differences1 = DIFF(expected_buf, buf1, self.fill_size)
            _changed1 = len(differences1) > 0

            if self.logger.VERBOSE:
                self.logger.log(f'Checking contents at PA 0x{_ptr:016X}:')
                print_buffer_bytes(buf1, 16)

            if _changed1:
                self.logger.log(f'    Contents changed at 0x{_ptr:016X} +{differences1}')
                if restore_contents:
                    self.logger.log(f'    Restoring 0x{self.fill_size:X} bytes at PA 0x{_ptr:016X}')
                    self.cs.mem.write_physical_mem(_ptr, self.fill_size, expected_buf)
                if DUMP_MEMORY_ON_DETECT:
                    _pth_smi = os.path.join(_pth, f'{_smi_desc.smi_code:X}_{_smi_desc.name}')
                    if not os.path.exists(_pth_smi):
                        os.makedirs(_pth_smi)
                    _f = os.path.join(_pth_smi, fn + (f'_ptr{_smi_desc.ptr_offset:X}.dmp'))
                    self.logger.log(f'    Dumping buffer to \'{_f}\'')
                    write_file(_f, buf1)

        return (_changed or _changed1)

    def smi_fuzz_iter(self, thread_id, _addr, _smi_desc, fill_contents=True, restore_contents=False, scan=None):
        #
        # Fill memory buffer if not in 'No Fill' mode
        #
        if self.is_check_memory and fill_contents:
            self.fill_memory(_addr, _smi_desc.ptr_in_buffer, _smi_desc.ptr, _smi_desc.ptr_offset, _smi_desc.sig, _smi_desc.sig_offset)

        if FLUSH_OUTPUT_BEFORE_SMI:
            self.logger.flush()
        #
        # Invoke SW SMI Handler
        #
        _rax = _smi_desc.gprs['rax']
        _rbx = _smi_desc.gprs['rbx']
        _rcx = _smi_desc.gprs['rcx']
        _rdx = _smi_desc.gprs['rdx']
        _rsi = _smi_desc.gprs['rsi']
        _rdi = _smi_desc.gprs['rdi']
        if not scan:
            self.send_smi(thread_id, _smi_desc.smi_code, _smi_desc.smi_data, _smi_desc.name, _smi_desc.desc, _rax, _rbx, _rcx, _rdx, _rsi, _rdi)
        else:
            while True:
                _, duration = self.send_smi_timed(thread_id, _smi_desc.smi_code, _smi_desc.smi_data, _smi_desc.name, _smi_desc.desc, _rax, _rbx, _rcx, _rdx, _rsi, _rdi)
                if scan.valid_smi_count():
                    break
            #
            # Re-do the call if it was identified as an outlier, due to periodic SMI delays
            #
            if scan.is_outlier(duration):
                while True:
                    _, duration = self.send_smi_timed(thread_id, _smi_desc.smi_code, _smi_desc.smi_data, _smi_desc.name, _smi_desc.desc, _rax, _rbx, _rcx, _rdx, _rsi, _rdi)
                    if scan.valid_smi_count():
                        break
        #
        # Check memory buffer if not in 'No Fill' mode
        #
        contents_changed = False
        if self.is_check_memory:
            fn = f'{_smi_desc.smi_data:X}-a{_rax:X}_b{_rbx:X}_c{_rcx:X}_d{_rdx:X}_si{_rsi:X}_di{_rdi:X}'
            contents_changed = self.check_memory(_addr, _smi_desc, fn, restore_contents)
            if contents_changed:
                msg = f'DETECTED: SMI# {_smi_desc.smi_code:X} data {_smi_desc.smi_data:X} (rax={_rax:X} rbx={_rbx:X} rcx={_rcx:X} rdx={_rdx:X} rsi={_rsi:X} rdi={_rdi:X})'
                self.logger.log_important(msg)
                if FUZZ_BAIL_ON_1ST_DETECT and not scan:
                    raise BadSMIDetected(msg)

        if scan:
            scan.add(duration, _smi_desc.smi_code, _smi_desc.smi_data, _smi_desc.gprs, contents_changed)

        if FLUSH_OUTPUT_AFTER_SMI:
            self.logger.flush()

        return contents_changed

    def test_config(self, thread_id, _smi_config_fname, _addr, _addr1):
        #
        # Parse SMM config file describing SMI handlers and their call arguments
        # Then invoke SMI handlers
        #
        fcfg = open(_smi_config_fname, 'r')
        self.logger.log(f'\n[*] >>> Testing SMI handlers defined in \'{_smi_config_fname}\'..')

        bad_ptr_cnt = 0
        _smi_desc = smi_desc()
        for line in fcfg:
            if '' == line.strip():
                self.logger.log(f'\n[*] Testing SMI# 0x{_smi_desc.smi_code:02X} (data: 0x{_smi_desc.smi_data:02X}) {_smi_desc.name} ({_smi_desc.desc})')
                if self.smi_fuzz_iter(thread_id, _addr, _smi_desc):
                    bad_ptr_cnt += 1
                _smi_desc = None
                _smi_desc = smi_desc()
            else:
                name, var = line.strip().partition('=')[::2]
                _n = name.strip().lower()
                if 'name' == _n:
                    _smi_desc.name = var
                elif 'desc' == _n:
                    _smi_desc.desc = var
                elif 'smi_code' == _n:
                    _smi_desc.smi_code = int(var, 16) if '*' != var else _SMI_CODE_DATA
                elif 'smi_data' == _n:
                    _smi_desc.smi_data = int(var, 16) if '*' != var else _SMI_CODE_DATA
                elif 'ptr_offset' == _n:
                    _smi_desc.ptr_in_buffer = True
                    _smi_desc.ptr_offset = int(var, 16)
                    _smi_desc.ptr = _addr1
                elif 'sig' == _n:
                    _smi_desc.sig = bytearray.fromhex(var)
                elif 'sig_offset' == _n:
                    _smi_desc.sig_offset = int(var, 16)
                else:
                    _smi_desc.gprs[_n] = (_addr if 'PTR' == var else (_FILL_VALUE_BYTE if 'VAL' == var else int(var, 16))) if '*' != var else _FILL_VALUE_QWORD

        return bad_ptr_cnt

    def test_fuzz(self, thread_id, smic_start, smic_end, _addr, _addr1, scan_mode=False):

        scan = None
        if scan_mode:
            scan = scan_track()

        gpr_value = ((_addr << 32) | _addr) if GPR_2ADDR else _addr

        gprs_addr = {'rax': gpr_value, 'rbx': gpr_value, 'rcx': gpr_value, 'rdx': gpr_value, 'rsi': gpr_value, 'rdi': gpr_value}
        gprs_fill = {'rax': _FILL_VALUE_QWORD, 'rbx': _FILL_VALUE_QWORD, 'rcx': _FILL_VALUE_QWORD, 'rdx': _FILL_VALUE_QWORD, 'rsi': _FILL_VALUE_QWORD, 'rdi': _FILL_VALUE_QWORD}
        self.logger.log("\n[*] >>> Fuzzing SMI handlers..")
        self.logger.log("[*] AX in RAX will be overridden with values of SW SMI ports 0xB2/0xB3")
        self.logger.log("    DX in RDX will be overridden with value 0x00B2")

        bad_ptr_cnt = 0
        _smi_desc = smi_desc()
        _smi_desc.gprs = gprs_addr if PTR_IN_ALL_GPRS or scan_mode else gprs_fill
        self.logger.log(f'\n[*] Setting values of general purpose registers to 0x{_smi_desc.gprs["rax"]:016X}')
        max_ptr_off = 1

        if self.is_check_memory and self.test_ptr_in_buffer:
            _smi_desc.ptr_in_buffer = True
            _smi_desc.ptr = _addr1
            max_ptr_off = MAX_PTR_OFFSET_IN_BUFFER + 1

        # if we are not in fuzzmore mode, i.e. we are not testing the pointer within memory buffer
        # then this outer loop will only have 1 iteration
        for off in range(max_ptr_off):
            _smi_desc.ptr_offset = off
            self.logger.log(f'\n[*] Reloading buffer with PTR at offset 0x{off:X}..')
            if self.is_check_memory:
                self.fill_memory(_addr, _smi_desc.ptr_in_buffer, _smi_desc.ptr, _smi_desc.ptr_offset, None, None)

            for smi_code in range(smic_start, smic_end + 1, 1):
                _smi_desc.smi_code = smi_code
                for smi_data in range(MAX_SMI_DATA):
                    _smi_desc.smi_data = smi_data
                    self.logger.log(f'\n[*] Fuzzing SMI# 0x{smi_code:02X} (data: 0x{smi_data:02X})')
                    if FUZZ_SMI_FUNCTIONS_IN_ECX:
                        for _rcx in range(MAX_SMI_FUNCTIONS):
                            self.logger.log(f' >> Function (RCX): 0x{_rcx:016X}')
                            _smi_desc.gprs['rcx'] = _rcx
                            if PTR_IN_ALL_GPRS or scan_mode:
                                if self.smi_fuzz_iter(thread_id, _addr, _smi_desc, False, True, scan):
                                    bad_ptr_cnt += 1
                                if scan and scan.skip():
                                    break
                            else:
                                self.logger.log(f'    RBX: 0x{_addr:016X}')
                                _smi_desc.gprs['rbx'] = gpr_value
                                if self.smi_fuzz_iter(thread_id, _addr, _smi_desc, False, True):
                                    bad_ptr_cnt += 1
                                _smi_desc.gprs['rbx'] = _FILL_VALUE_QWORD

                                self.logger.log(f'    RSI: 0x{_addr:016X}')
                                _smi_desc.gprs['rsi'] = gpr_value
                                if self.smi_fuzz_iter(thread_id, _addr, _smi_desc, False, True):
                                    bad_ptr_cnt += 1
                                _smi_desc.gprs['rsi'] = _FILL_VALUE_QWORD

                                self.logger.log(f'    RDI: 0x{_addr:016X}')
                                _smi_desc.gprs['rdi'] = gpr_value
                                if self.smi_fuzz_iter(thread_id, _addr, _smi_desc, False, True):
                                    bad_ptr_cnt += 1
                                _smi_desc.gprs['rdi'] = _FILL_VALUE_QWORD
                    else:
                        if PTR_IN_ALL_GPRS or scan_mode:
                            if self.smi_fuzz_iter(thread_id, _addr, _smi_desc, False, True, scan):
                                bad_ptr_cnt += 1
                        else:
                            self.logger.log(f'    RBX: 0x{_addr:016X}')
                            _smi_desc.gprs['rbx'] = gpr_value
                            if self.smi_fuzz_iter(thread_id, _addr, _smi_desc, False, True):
                                bad_ptr_cnt += 1
                            _smi_desc.gprs['rbx'] = _FILL_VALUE_QWORD

                            self.logger.log(f'    RCX: 0x{_addr:016X}')
                            _smi_desc.gprs['rcx'] = gpr_value
                            if self.smi_fuzz_iter(thread_id, _addr, _smi_desc, False, True):
                                bad_ptr_cnt += 1
                            _smi_desc.gprs['rcx'] = _FILL_VALUE_QWORD

                            self.logger.log(f'    RSI: 0x{_addr:016X}')
                            _smi_desc.gprs['rsi'] = gpr_value
                            if self.smi_fuzz_iter(thread_id, _addr, _smi_desc, False, True):
                                bad_ptr_cnt += 1
                            _smi_desc.gprs['rsi'] = _FILL_VALUE_QWORD

                            self.logger.log(f'    RDI: 0x{_addr:016X}')
                            _smi_desc.gprs['rdi'] = gpr_value
                            if self.smi_fuzz_iter(thread_id, _addr, _smi_desc, False, True):
                                bad_ptr_cnt += 1
                            _smi_desc.gprs['rdi'] = _FILL_VALUE_QWORD
                    if scan and scan.skip():
                        break
                if scan_mode:
                    scan.log_smi_result(self.logger)
                    scan.clear()

        return bad_ptr_cnt, scan

    def run(self, module_argv):
        self.logger.start_test("A tool to test SMI handlers for pointer validation vulnerabilities")
        self.logger.log("Usage: chipsec_main -m tools.smm.smm_ptr [ -a <mode>,<config_file>|<smic_start:smic_end>,<size>,<address> ]")
        self.logger.log("  mode          SMI handlers testing mode")
        self.logger.log("    = config    use SMI configuration file <config_file>")
        self.logger.log("    = fuzz      fuzz all SMI handlers with code in the range <smic_start:smic_end>")
        self.logger.log("    = fuzzmore  fuzz mode + pass '2nd-order' pointers within buffer to SMI handlers")
        self.logger.log("    = scan      fuzz mode + time measurement to identify SMIs that trigger long-running code paths")
        self.logger.log("  size          size of the memory buffer (in Hex)")
        self.logger.log("  address       physical address of memory buffer to pass in GP regs to SMI handlers (in Hex)")
        self.logger.log("    = smram     pass address of SMRAM base (system may hang in this mode!)\n")

        test_mode = 'config'
        _smi_config_fname = 'chipsec/modules/tools/smm/smm_config.ini'
        _addr = None
        _addr1 = None
        thread_id = 0x0

        global DUMP_GPRS_EVERY_SMI
        smic_start = 0
        smic_end = 0
        if len(module_argv) > 1:
            test_mode = module_argv[0].lower()
            if test_mode == 'config':
                _smi_config_fname = module_argv[1]
            elif test_mode in ['fuzz', 'fuzzmore', 'scan']:
                smic_arr = module_argv[1].split(':')
                smic_start = int(smic_arr[0], 16)
                smic_end = int(smic_arr[1], 16)
                if test_mode == 'fuzzmore':
                    self.test_ptr_in_buffer = True
                    DUMP_GPRS_EVERY_SMI = False
                elif test_mode == 'scan':
                    self.test_ptr_in_buffer = False
            else:
                self.logger.log_error(f'Unknown fuzzing mode \'{module_argv[0]}\'')
                self.result.setStatusBit(self.result.status.UNSUPPORTED_OPTION)
                return self.result.getReturnCode(ModuleResult.ERROR)

        if len(module_argv) > 2:
            self.fill_size = int(module_argv[2], 16)
        if len(module_argv) > 3:
            if 'smram' == module_argv[3]:
                (_addr, _, _) = self.cs.cpu.get_SMRAM()
                self.is_check_memory = False
                self.logger.log(f'[*] Using SMRAM base address (0x{_addr:016X}) to pass to SMI handlers')
            else:
                _addr = int(module_argv[3], 16)
                self.logger.log(f'[*] Using address from command-line (0x{_addr:016X}) to pass to SMI handlers')
        else:
            (_, _addr) = self.cs.mem.alloc_physical_mem(self.fill_size, _MAX_ALLOC_PA)
            self.logger.log(f'[*] Allocated memory buffer (to pass to SMI handlers)       : 0x{_addr:016X}')

        if self.is_check_memory:
            (_, _addr1) = self.cs.mem.alloc_physical_mem(self.fill_size, _MAX_ALLOC_PA)
            self.logger.log(f'[*] Allocated 2nd buffer (address will be in the 1st buffer): 0x{_addr1:016X}')

        #
        # @TODO: Need to check that SW/APMC SMI is enabled
        #

        self.logger.log('\n[*] Configuration:')
        self.logger.log(f'    SMI testing mode          : {test_mode}')
        if test_mode == 'config':
            self.logger.log(f'    Config file           : {_smi_config_fname}')
        else:
            self.logger.log(f'    Range of SMI codes (B2)   : 0x{smic_start:02X}:0x{smic_end:02X}')
        self.logger.log(f'    Memory buffer pointer     : 0x{_addr:016X} (address passed in GP regs to SMI)')
        self.logger.log(f'    Filling/checking memory?  : {"YES" if self.is_check_memory else "NO"}')
        if self.is_check_memory:
            self.logger.log(f'      Second buffer pointer   : 0x{_addr1:016X} (address written to memory buffer)')
            self.logger.log(f'      Number of bytes to fill : 0x{self.fill_size:X}')
            self.logger.log(f'      Byte to fill with       : 0x{ord(self.fill_byte):X}')
        self.logger.log(f'    Additional options (can be changed in the source code):f')
        self.logger.log(f'      Fuzzing SMI functions in ECX?          : {FUZZ_SMI_FUNCTIONS_IN_ECX:d}')
        self.logger.log(f'      Max value of SMI function in ECX       : 0x{MAX_SMI_FUNCTIONS:X}')
        self.logger.log(f'      Max value of SMI data (B3)             : 0x{MAX_SMI_DATA:X}')
        self.logger.log(f'      Max offset of the pointer in the buffer: 0x{MAX_PTR_OFFSET_IN_BUFFER:X}')
        self.logger.log(f'      Passing pointer in all GP registers?   : {PTR_IN_ALL_GPRS:d}')
        self.logger.log(f'      Default values of the registers        : 0x{_FILL_VALUE_QWORD:016X}')
        self.logger.log(f'      Dump all register values every SMI     : {DUMP_GPRS_EVERY_SMI:d}')
        self.logger.log(f'      Bail on first detection                : {FUZZ_BAIL_ON_1ST_DETECT:d}')

        self.logger.set_always_flush(FLUSH_OUTPUT_ALWAYS)
        if DUMP_MEMORY_ON_DETECT and not os.path.exists(_pth):
            os.makedirs(_pth)

        bad_ptr_cnt = 0
        scan_mode = False
        try:
            if 'config' == test_mode:
                bad_ptr_cnt = self.test_config(thread_id, _smi_config_fname, _addr, _addr1)
            elif test_mode in ['fuzz', 'fuzzmore']:
                bad_ptr_cnt, _ = self.test_fuzz(thread_id, smic_start, smic_end, _addr, _addr1)
            elif test_mode in ['scan']:
                scan_mode =  True
                scan = None
                bad_ptr_cnt, scan = self.test_fuzz(thread_id, smic_start, smic_end, _addr, _addr1, True)
        except BadSMIDetected as msg:
            bad_ptr_cnt = 1
            self.logger.log_important("Potentially bad SMI detected! Stopped fuzing (see FUZZ_BAIL_ON_1ST_DETECT option)")

        if scan_mode and scan:
            self.logger.log_good(f'<<< Done: found {scan.get_total_outliers()} long-running SMIs')
        if bad_ptr_cnt > 0:
            self.logger.log_bad(f'<<< Done: found {bad_ptr_cnt:d} potential occurrences of unchecked input pointers')
            self.result.setStatusBit(self.result.status.POTENTIALLY_VULNERABLE)
            self.res = self.result.getReturnCode(ModuleResult.FAILED)
        else:
            self.logger.log_good("<<< Done: didn't find unchecked input pointers in tested SMI handlers")
            self.result.setStatusBit(self.result.status.SUCCESS)
            self.res = self.result.getReturnCode(ModuleResult.PASSED)

        return self.res
