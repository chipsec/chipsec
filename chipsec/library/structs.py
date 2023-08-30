# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2023, Intel Corporation
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
from typing import Dict


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


def pack1(value: int, size: int) -> bytes:
    """Shortcut to pack a single value into a string based on its size."""
    return struct.pack(SIZE2FORMAT[size], value)


def unpack1(string: bytes, size: int) -> int:
    """Shortcut to unpack a single value from a string based on its size."""
    return struct.unpack(SIZE2FORMAT[size], string)[0]
