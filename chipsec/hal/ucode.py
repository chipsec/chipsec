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
Microcode update specific functionality (for each CPU thread)

usage:
    >>> ucode_update_id( 0 )
    >>> load_ucode_update( 0, ucode_buf )
    >>> update_ucode_all_cpus( 'ucode.pdb' )
    >>> dump_ucode_update_header( 'ucode.pdb' )
"""

import struct
import os
from typing import AnyStr
from chipsec.library.logger import logger
from chipsec.library.file import read_file

IA32_MSR_BIOS_UPDT_TRIG = 0x79
IA32_MSR_BIOS_SIGN_ID = 0x8B
IA32_MSR_BIOS_SIGN_ID_STATUS = 0x1


from collections import namedtuple


class UcodeUpdateHeader(namedtuple('UcodeUpdateHeader', 'header_version update_revision date processor_signature checksum loader_revision processor_flags data_size total_size reserved1 reserved2 reserved3')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
Microcode Update Header
--------------------------------
Header Version      : 0x{self.header_version:08X}
Update Revision     : 0x{self.update_revision:08X}
Date                : 0x{self.date:08X}
Processor Signature : 0x{self.processor_signature:08X}
Checksum            : 0x{self.checksum:08X}
Loader Revision     : 0x{self.loader_revision:08X}
Processor Flags     : 0x{self.processor_flags:08X}
Update Data Size    : 0x{self.data_size:08X}
Total Size          : 0x{self.total_size:08X}
Reserved1           : 0x{self.reserved1:08X}
Reserved2           : 0x{self.reserved2:08X}
Reserved3           : 0x{self.reserved3:08X}
"""


UCODE_HEADER_SIZE = 0x30


def dump_ucode_update_header(pdb_ucode_buffer: bytes) -> UcodeUpdateHeader:
    ucode_header = UcodeUpdateHeader(*struct.unpack_from('12I', pdb_ucode_buffer))
    logger().log_hal(str(ucode_header))
    return ucode_header


def read_ucode_file(ucode_filename: str) -> bytes:
    ucode_buf = read_file(ucode_filename)
    if (ucode_filename.endswith('.pdb')):
        logger().log_hal(f"[ucode] PDB file '{ucode_filename:256}' has ucode update header (size = 0x{UCODE_HEADER_SIZE:X})")
        dump_ucode_update_header(ucode_buf)
        return ucode_buf[UCODE_HEADER_SIZE:]
    else:
        return ucode_buf


class Ucode:
    def __init__(self, cs):
        self.helper = cs.helper
        self.cs = cs

    # @TODO remove later/replace with msr.get_cpu_thread_count()
    def get_cpu_thread_count(self) -> int:
        thread_count = self.cs.register.read_field("IA32_MSR_CORE_THREAD_COUNT", "Thread_Count")
        return thread_count

    def ucode_update_id(self, cpu_thread_id: int) -> int:
        (bios_sign_id_lo, bios_sign_id_hi) = self.helper.read_msr(cpu_thread_id, IA32_MSR_BIOS_SIGN_ID)
        ucode_update_id = bios_sign_id_hi

        if (bios_sign_id_lo & IA32_MSR_BIOS_SIGN_ID_STATUS):
            logger().log_hal(f'[ucode] CPU{cpu_thread_id:d}: last Microcode update failed (current microcode id = 0x{ucode_update_id:08X})')
        else:
            logger().log_hal(f'[ucode] CPU{cpu_thread_id:d}: Microcode update ID = 0x{ucode_update_id:08X}')

        return ucode_update_id

    def update_ucode_all_cpus(self, ucode_file: str) -> bool:
        if not (os.path.exists(ucode_file) and os.path.isfile(ucode_file)):
            logger().log_error(f"Ucode file not found: '{ucode_file:.256}'")
            return False
        ucode_buf = read_ucode_file(ucode_file)
        if (ucode_buf is not None) and (len(ucode_buf) > 0):
            for tid in range(self.get_cpu_thread_count()):
                self.load_ucode_update(tid, ucode_buf)
        return True

    def update_ucode(self, cpu_thread_id: int, ucode_file: str) -> int:
        if not (os.path.exists(ucode_file) and os.path.isfile(ucode_file)):
            logger().log_error(f"Ucode file not found: '{ucode_file:.256}'")
            return False
        _ucode_buf = read_ucode_file(ucode_file)
        return self.load_ucode_update(cpu_thread_id, _ucode_buf)

    def load_ucode_update(self, cpu_thread_id: int, ucode_buf: AnyStr) -> int:
        logger().log_hal(f'[ucode] Loading microcode update on CPU{cpu_thread_id:d}')
        self.helper.load_ucode_update(cpu_thread_id, ucode_buf)
        return self.ucode_update_id(cpu_thread_id)
