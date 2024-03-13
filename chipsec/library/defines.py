# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2022, Intel Corporation
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

import struct
import os
import string
import platform
from typing import Any, Dict, Tuple, Optional, AnyStr, Iterable
from chipsec.library.file import get_main_dir

BIT0 = 0x0001
BIT1 = 0x0002
BIT2 = 0x0004
BIT3 = 0x0008
BIT4 = 0x0010
BIT5 = 0x0020
BIT6 = 0x0040
BIT7 = 0x0080
BIT8 = 0x0100
BIT9 = 0x0200
BIT10 = 0x0400
BIT11 = 0x0800
BIT12 = 0x1000
BIT13 = 0x2000
BIT14 = 0x4000
BIT15 = 0x8000
BIT16 = 0x00010000
BIT17 = 0x00020000
BIT18 = 0x00040000
BIT19 = 0x00080000
BIT20 = 0x00100000
BIT21 = 0x00200000
BIT22 = 0x00400000
BIT23 = 0x00800000
BIT24 = 0x01000000
BIT25 = 0x02000000
BIT26 = 0x04000000
BIT27 = 0x08000000
BIT28 = 0x10000000
BIT29 = 0x20000000
BIT30 = 0x40000000
BIT31 = 0x80000000
BIT32 = 0x100000000
BIT33 = 0x200000000
BIT34 = 0x400000000
BIT35 = 0x800000000
BIT36 = 0x1000000000
BIT37 = 0x2000000000
BIT38 = 0x4000000000
BIT39 = 0x8000000000
BIT40 = 0x10000000000
BIT41 = 0x20000000000
BIT42 = 0x40000000000
BIT43 = 0x80000000000
BIT44 = 0x100000000000
BIT45 = 0x200000000000
BIT46 = 0x400000000000
BIT47 = 0x800000000000
BIT48 = 0x1000000000000
BIT49 = 0x2000000000000
BIT50 = 0x4000000000000
BIT51 = 0x8000000000000
BIT52 = 0x10000000000000
BIT53 = 0x20000000000000
BIT54 = 0x40000000000000
BIT55 = 0x80000000000000
BIT56 = 0x100000000000000
BIT57 = 0x200000000000000
BIT58 = 0x400000000000000
BIT59 = 0x800000000000000
BIT60 = 0x1000000000000000
BIT61 = 0x2000000000000000
BIT62 = 0x4000000000000000
BIT63 = 0x8000000000000000

BOUNDARY_1KB = 0x400
BOUNDARY_2KB = 0x800
BOUNDARY_4KB = 0x1000
BOUNDARY_1MB = 0x100000
BOUNDARY_2MB = 0x200000
BOUNDARY_4MB = 0x400000
BOUNDARY_8MB = 0x800000
BOUNDARY_16MB = 0x1000000
BOUNDARY_32MB = 0x2000000
BOUNDARY_64MB = 0x4000000
BOUNDARY_128MB = 0x8000000
BOUNDARY_256MB = 0x10000000
BOUNDARY_512MB = 0x20000000
BOUNDARY_1GB = 0x40000000
BOUNDARY_2GB = 0x80000000
BOUNDARY_4GB = 0x100000000

ALIGNED_4KB = 0xFFF
ALIGNED_1MB = 0xFFFFF
ALIGNED_8MB = 0x7FFFFF
ALIGNED_64MB = 0x3FFFFFF
ALIGNED_128MB = 0x7FFFFFF
ALIGNED_256MB = 0xFFFFFFF

MASK_8b = 0xFF
MASK_16b = 0xFFFF
MASK_32b = 0xFFFFFFFF
MASK_64b = 0xFFFFFFFFFFFFFFFF


def bit(bit_num: int) -> int:
    return int(1 << bit_num)


def is_set(val: int, bit_mask: int) -> bool:
    return bool(val & bit_mask != 0)


def scan_single_bit_mask(bit_mask: int) -> Optional[int]:
    for bit_num in range(0, 7):
        if bit_mask >> bit_num == 1:
            return bit_num
    return None


def DB(val: int) -> bytes:
    return struct.pack('<B', val)


def DW(val: int) -> bytes:
    return struct.pack('<H', val)


def DD(val: int) -> bytes:
    return struct.pack('<L', val)


def DQ(val: int) -> bytes:
    return struct.pack('<Q', val)


SIZE2FORMAT: Dict[int, str] = {
    1: 'B',
    2: 'H',
    4: 'I',
    8: 'Q'
}


def bytestostring(mbytes: AnyStr) -> str:
    if isinstance(mbytes, bytes) or isinstance(mbytes, bytearray):
        return mbytes.decode("latin_1")
    else:
        return mbytes


def stringtobytes(mstr: AnyStr) -> bytes:
    if isinstance(mstr, str):
        return mstr.encode("latin_1")
    else:
        return mstr


def pack1(value: int, size: int) -> bytes:
    """Shortcut to pack a single value into a string based on its size."""
    return struct.pack(SIZE2FORMAT[size], value)


def unpack1(string: bytes, size: int) -> int:
    """Shortcut to unpack a single value from a string based on its size."""
    return struct.unpack(SIZE2FORMAT[size], string)[0]


def get_bits(value: int, start: int, nbits: int) -> int:
    ret = value >> start
    ret &= (1 << nbits) - 1
    return ret


def get_version() -> str:
    version_strs = []
    chipsec_folder = os.path.abspath(get_main_dir())
    for fname in sorted([x for x in os.listdir(os.path.join(chipsec_folder, "chipsec")) if x.startswith('VERSION')]):
        version_file = os.path.join(chipsec_folder, "chipsec", fname)
        with open(version_file, "r") as verFile:
            version_strs.append(verFile.read().strip())
    return '-'.join(version_strs)


def os_version() -> Tuple[str, str, str, str]:
    return platform.system(), platform.release(), platform.version(), platform.machine()


def is_printable(seq: AnyStr) -> bool:
    return set(bytestostring(seq)).issubset(set(string.printable))


def is_hex(maybe_hex: Iterable) -> bool:
    return all(char in string.hexdigits for char in maybe_hex)


def is_all_ones(value: int, size: int, width: int = 8) -> bool:
    mask = (1 << (size * width)) - 1
    return (mask == (mask & value))


def get_message() -> str:
    msg_str = ""
    chipsec_folder = os.path.abspath(get_main_dir())
    msg_file = os.path.join(chipsec_folder, "chipsec", "MESSAGE")
    if os.path.exists(msg_file):
        with open(msg_file, "r") as msgFile:
            msg_str = msgFile.read()
    return msg_str


def is_all_value(value_list: list, value: Any) -> bool:
    '''Checks if all elements in a list are equal to a given value'''
    return all(n == value for n in value_list)


class ARCH_VID:
    INTEL = 0x8086
    AMD = 0x1022
